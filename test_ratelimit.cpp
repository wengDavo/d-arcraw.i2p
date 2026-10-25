// Rate limiting: token-bucket burst/refill math and per-key isolation, on a fake clock.
#include <cmath>
#include <cstdio>

#include "darcraw/ratelimit.hpp"
#include "check.hpp"

using namespace darcraw;

int main() {
    // burst then paced
    double t = 0.0;
    Clock clk = [&t]() { return t; };
    {
        TokenBucket tb(2.0, 2.0, clk);
        REQUIRE(tb.take() && tb.take());
        REQUIRE(!tb.take());
        t = 0.5;                       // 1 token at rate 2/s
        REQUIRE(tb.take());
        REQUIRE(!tb.take());
    }
    std::printf("bucket: bursts to capacity then paces at rate\n");

    // idle refill capped at capacity
    t = 0.0;
    {
        TokenBucket tb(1.0, 3.0, clk);
        t = 100.0;
        REQUIRE(tb.take() && tb.take() && tb.take());
        REQUIRE(!tb.take());
    }
    std::printf("bucket: idle refill capped at capacity\n");

    // wait_time
    t = 0.0;
    {
        TokenBucket tb(4.0, 4.0, clk);
        for (int i = 0; i < 4; i++) tb.take();
        REQUIRE(std::abs(tb.wait_time() - 0.25) < 1e-9);
    }
    std::printf("bucket: wait_time computed correctly\n");

    // per-key isolation
    t = 0.0;
    {
        PerKeyRateLimiter rl(1.0, 1.0, clk);
        REQUIRE(rl.allow("a.i2p"));
        REQUIRE(!rl.allow("a.i2p"));
        REQUIRE(rl.allow("b.i2p"));
    }
    std::printf("per-key: buckets isolated by key\n");

    // reap idle, keep active
    t = 0.0;
    {
        PerKeyRateLimiter rl(1.0, 1.0, clk);
        rl.allow("a.i2p");
        rl.allow("b.i2p");
        t = 100.0;
        rl.allow("b.i2p");             // b touched at t=100
        t = 350.0;                     // a idle 350s, b idle 250s
        rl.reap(300.0);
        REQUIRE(rl.size() == 1);       // only b survives
    }
    std::printf("per-key: idle buckets reaped, active ones kept\n");

    std::printf("ratelimit: all passed\n");
    return 0;
}
