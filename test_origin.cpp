// Origin classifier: Stage 1 signals and Stage 2 mirror detection with first-seen
// ordering, so re-crawling the original address is not self-flagged.
#include <cstdio>
#include <string>

#include "darcraw/origin.hpp"
#include "check.hpp"

using namespace darcraw;

int main() {
    // native: i2p links, no clearnet assets
    std::string native_page;
    for (int i = 0; i < 5; i++)
        native_page += "<a href=\"http://peer" + std::to_string(i) + ".i2p/x\">link</a>\n";
    REQUIRE(classify(native_page).type == "native");

    // unknown: nothing to go on
    REQUIRE(classify("<html><body>hello</body></html>").type == "unknown");
    std::printf("origin: Stage 1 native and unknown classified\n");

    // Stage 2 mirror: same content at a later address is flagged, the original is not
    TwoStageClassifier tsc;
    Bytes content = to_bytes(native_page);
    Origin first = tsc(content, "http://aaa.i2p/");
    REQUIRE(first.type != "mirror");                      // original keeps its label
    Origin second = tsc(content, "http://bbb.i2p/");
    REQUIRE(second.type == "mirror");                     // later copy flagged
    Origin recrawl = tsc(content, "http://aaa.i2p/");
    REQUIRE(recrawl.type != "mirror");                    // re-crawl of original not self-flagged
    std::printf("origin: Stage 2 flags the later copy, not the original on re-crawl\n");

    std::printf("origin: all passed\n");
    return 0;
}
