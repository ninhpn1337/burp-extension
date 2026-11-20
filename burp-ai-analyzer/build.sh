#!/usr/bin/env bash
# Build a self-contained Burp extension jar (ai-analyzer.jar) using only javac/jar.
set -euo pipefail
cd "$(dirname "$0")"

MONTOYA_VERSION="2026.7"
GSON_VERSION="2.10.1"

mkdir -p lib build/classes build/gson dist

if [ ! -f lib/montoya-api.jar ]; then
  curl -sL -o lib/montoya-api.jar \
    "https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/${MONTOYA_VERSION}/montoya-api-${MONTOYA_VERSION}.jar"
fi
if [ ! -f lib/gson.jar ]; then
  curl -sL -o lib/gson.jar \
    "https://repo1.maven.org/maven2/com/google/code/gson/gson/${GSON_VERSION}/gson-${GSON_VERSION}.jar"
fi

rm -rf build/classes build/gson
mkdir -p build/classes build/gson

echo "Compiling..."
find src -name '*.java' > build/sources.txt
CP_SEP=":"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) CP_SEP=";" ;;
esac
javac -encoding UTF-8 -cp "lib/montoya-api.jar${CP_SEP}lib/gson.jar" -d build/classes @build/sources.txt

echo "Bundling gson classes (runtime dependency not provided by Burp)..."
(cd build/gson && jar xf ../../lib/gson.jar)
rm -rf build/gson/META-INF

echo "Packaging dist/ai-analyzer.jar..."
rm -f dist/ai-analyzer.jar
jar cf dist/ai-analyzer.jar -C build/classes . -C build/gson .

echo "Done: dist/ai-analyzer.jar"
