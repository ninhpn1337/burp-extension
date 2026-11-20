package burp.ai;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Talks to any OpenAI-compatible endpoint (OpenAI, OpenRouter, LM Studio, vLLM,
 * recent Ollama /v1) with a fallback to Ollama's native /api endpoints, so the
 * user controls the base URL (local or self-hosted) instead of a fixed vendor server.
 */
public class AiClient {

    public static class ConnectResult {
        public final boolean ok;
        public final List<String> models;
        public final String error;

        ConnectResult(boolean ok, List<String> models, String error) {
            this.ok = ok;
            this.models = models;
            this.error = error;
        }
    }

    /** Optional sink for request/response diagnostics (wired to Burp's extension Output tab). */
    public interface DebugLog {
        void log(String line);
    }

    private final DebugLog debugLog;

    public AiClient() {
        this(line -> { });
    }

    public AiClient(DebugLog debugLog) {
        this.debugLog = debugLog != null ? debugLog : (line -> { });
    }

    private final HttpClient http = HttpClient.newBuilder()
            // Force a direct connection: never let the JVM's default ProxySelector
            // (which can pick up the OS system proxy - often Burp's own listener on
            // a pentest box) silently route these outbound AI calls through Burp's
            // proxy, where Match & Replace / interception rules can strip headers
            // like Authorization and turn a correct key into a 401.
            .proxy(HttpClient.Builder.NO_PROXY)
            // java.net.http.HttpClient defaults to preferring HTTP/2 and will try an
            // h2c upgrade even for plain http:// URLs. Many dev-server stacks (e.g.
            // Next.js dev servers, which is what the "vary: rsc, next-router-..."
            // response headers indicate here) don't implement that upgrade cleanly and
            // the connection just hangs until timeout - while curl/browsers/Python,
            // which all speak plain HTTP/1.1 to http:// endpoints, work fine. Force
            // HTTP/1.1 so we behave the same way.
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    public ConnectResult listModels(String baseUrl, String apiKey) {
        String base = normalize(baseUrl);
        String key = apiKey == null ? "" : apiKey.trim();

        String openAiError = null;
        try {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + "/v1/models"))
                    .timeout(Duration.ofSeconds(10))
                    .GET();
            if (!key.isEmpty()) {
                b.header("Authorization", "Bearer " + key);
            }
            debugLog.log("GET " + base + "/v1/models  (Authorization: " + (key.isEmpty() ? "<none>" : maskKey(key)) + ")");
            HttpResponse<String> resp = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
            debugLog.log("-> HTTP " + resp.statusCode() + describeBody(resp.body()));
            if (resp.statusCode() / 100 == 2) {
                List<String> models = parseOpenAiModels(resp.body());
                if (!models.isEmpty()) {
                    return new ConnectResult(true, models, null);
                }
                openAiError = "HTTP " + resp.statusCode() + " from " + base + "/v1/models but no models in response";
            } else if (resp.statusCode() == 401 || resp.statusCode() == 403) {
                // Definitive auth failure - don't mask it by falling through to the
                // Ollama-native probe, which would just report its own 401/404 instead.
                return new ConnectResult(false, List.of(),
                        "HTTP " + resp.statusCode() + " (unauthorized) from " + base + "/v1/models - "
                                + "check the API key, and that it's the key this server expects "
                                + (key.isEmpty() ? "(no key was sent)" : "(" + maskKey(key) + " was sent)")
                                + describeBody(resp.body()));
            } else {
                openAiError = "HTTP " + resp.statusCode() + " from " + base + "/v1/models" + describeBody(resp.body());
            }
        } catch (Exception e) {
            openAiError = base + "/v1/models: " + e.getMessage();
        }

        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(base + "/api/tags"))
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();
            debugLog.log("GET " + base + "/api/tags (Ollama-native fallback)");
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            debugLog.log("-> HTTP " + resp.statusCode() + describeBody(resp.body()));
            if (resp.statusCode() / 100 == 2) {
                List<String> models = parseOllamaModels(resp.body());
                if (!models.isEmpty()) {
                    return new ConnectResult(true, models, null);
                }
            }
            String tagsError = (resp.statusCode() == 401 || resp.statusCode() == 403)
                    ? "HTTP " + resp.statusCode() + " (unauthorized) from " + base + "/api/tags" + describeBody(resp.body())
                    : "HTTP " + resp.statusCode() + " from " + base + "/api/tags" + describeBody(resp.body());
            return new ConnectResult(false, List.of(), combine(openAiError, tagsError));
        } catch (Exception e) {
            return new ConnectResult(false, List.of(), combine(openAiError, base + "/api/tags: " + e.getMessage()));
        }
    }

    /** Always surface both probe results, since the real cause can be in either one. */
    private static String combine(String first, String second) {
        if (first == null) {
            return second;
        }
        return first + "  |  " + second;
    }

    private static String maskKey(String key) {
        if (key.length() <= 8) {
            return "***";
        }
        return key.substring(0, 4) + "..." + key.substring(key.length() - 4) + " (" + key.length() + " chars)";
    }

    private static String describeBody(String body) {
        if (body == null || body.isBlank()) {
            return "";
        }
        String trimmed = body.strip();
        if (trimmed.length() > 200) {
            trimmed = trimmed.substring(0, 200) + "...";
        }
        return " - body: " + trimmed;
    }

    private static final class PostResult {
        final String content;
        final String error;

        PostResult(String content, String error) {
            this.content = content;
            this.error = error;
        }
    }

    public String chat(String baseUrl, String apiKey, String model, String promptText) throws Exception {
        String base = normalize(baseUrl);
        String key = apiKey == null ? "" : apiKey.trim();

        JsonObject body = new JsonObject();
        body.addProperty("model", model);
        body.addProperty("stream", false);
        JsonArray messages = new JsonArray();
        JsonObject msg = new JsonObject();
        msg.addProperty("role", "user");
        msg.addProperty("content", promptText);
        messages.add(msg);
        body.add("messages", messages);

        PostResult openAi = postChat(base + "/v1/chat/completions", key, body, true);
        if (openAi.content != null) {
            return openAi.content;
        }

        PostResult ollama = postChat(base + "/api/chat", key, body, false);
        if (ollama.content != null) {
            return ollama.content;
        }

        throw new RuntimeException("AI endpoint at " + base + " did not return a usable response. "
                + combine(openAi.error, ollama.error));
    }

    private PostResult postChat(String url, String apiKey, JsonObject body, boolean openAiStyle) {
        try {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(180))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString()));
            if (apiKey != null && !apiKey.isBlank()) {
                b.header("Authorization", "Bearer " + apiKey);
            }
            debugLog.log("POST " + url);
            HttpResponse<String> resp = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
            debugLog.log("-> HTTP " + resp.statusCode() + describeBody(resp.body()));
            if (resp.statusCode() / 100 != 2) {
                return new PostResult(null, url + ": HTTP " + resp.statusCode() + describeBody(resp.body()));
            }
            JsonObject obj = JsonParser.parseString(resp.body()).getAsJsonObject();
            if (openAiStyle) {
                JsonArray choices = obj.getAsJsonArray("choices");
                if (choices != null && choices.size() > 0) {
                    JsonObject choice0 = choices.get(0).getAsJsonObject();
                    JsonObject message = choice0.getAsJsonObject("message");
                    if (message != null && message.has("content")) {
                        return new PostResult(message.get("content").getAsString(), null);
                    }
                }
                return new PostResult(null, url + ": HTTP " + resp.statusCode()
                        + " but no choices[0].message.content in response" + describeBody(resp.body()));
            } else {
                JsonObject message = obj.getAsJsonObject("message");
                if (message != null && message.has("content")) {
                    return new PostResult(message.get("content").getAsString(), null);
                }
                return new PostResult(null, url + ": HTTP " + resp.statusCode()
                        + " but no message.content in response" + describeBody(resp.body()));
            }
        } catch (Exception e) {
            return new PostResult(null, url + ": " + e);
        }
    }

    /**
     * One turn of an OpenAI-style tool-calling conversation: sends the full message history plus
     * the available tool definitions, returns the raw assistant "message" object (which may carry
     * "content", "tool_calls", or both) so the caller can append it to the conversation and execute
     * any requested tool calls itself. Used by the agent loop, which needs multi-turn state that a
     * single chat() call doesn't model. Only the OpenAI-compatible endpoint supports tool calling -
     * there is no Ollama-native fallback here.
     */
    public JsonObject chatWithTools(String baseUrl, String apiKey, String model, JsonArray messages, JsonArray tools)
            throws Exception {
        String base = normalize(baseUrl);
        String key = apiKey == null ? "" : apiKey.trim();

        JsonObject body = new JsonObject();
        body.addProperty("model", model);
        body.addProperty("stream", false);
        body.add("messages", messages);
        if (tools != null && tools.size() > 0) {
            body.add("tools", tools);
            body.addProperty("tool_choice", "auto");
        }

        String url = base + "/v1/chat/completions";
        try {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(180))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString()));
            if (!key.isEmpty()) {
                b.header("Authorization", "Bearer " + key);
            }
            debugLog.log("POST " + url + " (agent turn)");
            HttpResponse<String> resp = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
            debugLog.log("-> HTTP " + resp.statusCode() + describeBody(resp.body()));
            if (resp.statusCode() / 100 != 2) {
                throw new RuntimeException(url + ": HTTP " + resp.statusCode() + describeBody(resp.body()));
            }
            JsonObject obj = JsonParser.parseString(resp.body()).getAsJsonObject();
            JsonArray choices = obj.getAsJsonArray("choices");
            if (choices == null || choices.size() == 0) {
                throw new RuntimeException(url + ": HTTP " + resp.statusCode() + " but no choices in response"
                        + describeBody(resp.body()));
            }
            JsonObject message = choices.get(0).getAsJsonObject().getAsJsonObject("message");
            if (message == null) {
                throw new RuntimeException(url + ": HTTP " + resp.statusCode() + " but choices[0].message missing"
                        + describeBody(resp.body()));
            }
            if (!message.has("role")) {
                message.addProperty("role", "assistant");
            }
            return message;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(url + ": " + e, e);
        }
    }

    private List<String> parseOpenAiModels(String body) {
        List<String> out = new ArrayList<>();
        try {
            JsonObject obj = JsonParser.parseString(body).getAsJsonObject();
            JsonArray data = obj.getAsJsonArray("data");
            if (data != null) {
                for (JsonElement e : data) {
                    JsonObject m = e.getAsJsonObject();
                    if (m.has("id")) {
                        out.add(m.get("id").getAsString());
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    private List<String> parseOllamaModels(String body) {
        List<String> out = new ArrayList<>();
        try {
            JsonObject obj = JsonParser.parseString(body).getAsJsonObject();
            JsonArray models = obj.getAsJsonArray("models");
            if (models != null) {
                for (JsonElement e : models) {
                    JsonObject m = e.getAsJsonObject();
                    if (m.has("name")) {
                        out.add(m.get("name").getAsString());
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    private String normalize(String baseUrl) {
        String b = baseUrl.trim();
        while (b.endsWith("/")) {
            b = b.substring(0, b.length() - 1);
        }
        // We always append "/v1/..." or "/api/..." ourselves, so strip a trailing
        // "/v1" the user may already have typed (e.g. "http://host:port/v1") to
        // avoid requesting "/v1/v1/models" and getting a 404.
        if (b.regionMatches(true, b.length() - 3, "/v1", 0, 3)) {
            b = b.substring(0, b.length() - 3);
        }
        // On some Windows setups the JVM resolves "localhost" to the IPv6 loopback
        // (::1) first; if the target server only binds IPv4 (127.0.0.1), the connect
        // attempt hangs until timeout instead of failing fast. Pin to IPv4 loopback
        // to avoid that - curl/browsers usually prefer IPv4 and don't hit this.
        b = b.replaceFirst("(?i)^(https?://)localhost([:/]|$)", "$1127.0.0.1$2");
        return b;
    }
}
