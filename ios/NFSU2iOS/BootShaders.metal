#include <metal_stdlib>
using namespace metal;

struct BootVertex {
    float4 position [[position]];
    float2 uv;
};

vertex BootVertex bootVertex(uint vertexID [[vertex_id]]) {
    const float2 positions[3] = {
        float2( 0.0,  0.78),
        float2(-0.85, -0.78),
        float2( 0.85, -0.78)
    };
    BootVertex out;
    out.position = float4(positions[vertexID], 0.0, 1.0);
    out.uv = positions[vertexID] * 0.5 + 0.5;
    return out;
}

fragment half4 bootFragment(BootVertex in [[stage_in]]) {
    float stripe = 1.0 - smoothstep(0.03, 0.13, abs(in.uv.x - 0.5));
    float3 asphalt = float3(0.11, 0.22, 0.25);
    float3 paint = float3(0.37, 0.97, 0.77);
    float3 color = mix(asphalt, paint, stripe);
    return half4(half3(color), half(1.0));
}
