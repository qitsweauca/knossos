#version 120

uniform mat4 modelview_matrix;
uniform mat4 projection_matrix;
uniform vec4 viewport;
uniform float zoom;

varying vec2 node_center_ndc;
varying float frag_radius;
varying vec4 frag_color;
varying vec3 light_normal;

void main() {
    vec2 vp_center = 0.5 * viewport.zw;
    vec2 frag_pos_ndc = ((gl_FragCoord.xy - viewport.xy) - vp_center) / vp_center;

    vec2 frag_offset = frag_pos_ndc - node_center_ndc;
    float dist_squared = dot(frag_offset, frag_offset);
    float size_squared = pow(2 * zoom * frag_radius / viewport.z, 2);

    if (dist_squared > size_squared) {
        discard;
//        gl_FragColor = frag_color;
    } else {
//        vec3 light_normal = normalize((projection_matrix * modelview_matrix * gl_LightSource[0].position).xyz - gl_FragCoord.xyz);
        vec3 light_normal = normalize(gl_LightSource[0].position - gl_FragCoord).xyz;
        float dist_edge = sqrt(size_squared) - sqrt(dist_squared);
        vec3 frag_normal = normalize(vec3(frag_offset, dist_edge));
        float intensity = max(0.0, dot(light_normal, frag_normal));
        gl_FragColor = frag_color * (gl_LightModel.ambient + intensity + gl_LightSource[0].ambient);
        gl_FragDepth = gl_FragCoord.z + dist_edge * gl_DepthRange.diff / 2.0 * gl_ProjectionMatrix[2].z;
    }
}
