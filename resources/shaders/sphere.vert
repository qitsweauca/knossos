#version 120

attribute vec3 vertex;
attribute vec4 color;
attribute float radius;

uniform vec4 viewport;

uniform mat4 modelview_matrix;
uniform mat4 projection_matrix;
uniform float zoom;

varying vec2 node_center_ndc;
varying float frag_radius;
varying vec4 frag_color;

void main() {
    mat4 mvp_matrix = projection_matrix * modelview_matrix;
    gl_Position = mvp_matrix * vec4(vertex, 1.0);

    gl_PointSize = 2 * zoom * radius;

    node_center_ndc = gl_Position.xy;
    frag_radius = radius;
    frag_color = color;
}
