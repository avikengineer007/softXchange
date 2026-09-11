#!/usr/bin/env node
/**
 * softXchange — 3D Logo glTF Generator
 * Produces logo-hi.glb (Tier A, ~48 triangles) and logo-lo.glb (Tier B, ~20 triangles)
 *
 * Zero npm dependencies. Hand-authored glTF 2.0 binary (.glb) format:
 *   12-byte GLB header
 *   JSON chunk  (glTF scene descriptor)
 *   BIN  chunk  (vertex + index buffers as raw ArrayBuffer)
 *
 * The bowtie/hourglass shape: two arrow prisms pointing toward each other.
 * Each prism: triangular cross-section extruded along Z, 5 faces (2 tri + 3 quad→2tri each = 8 tris per prism).
 * Center bridge quad connecting the two tips: 2 tris.
 * Hi model adds chamfer rings at each tip: +12 tris.
 * Total hi: 2*(8) + 2 + 12 = 30 tris → with bevel geometry ~48 tris.
 *
 * Brand colors for material emissive hints are stored as extras so the web/Android
 * renderer can read them; actual PBR material creation is done at runtime.
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const OUT_DIR = path.resolve(__dirname);

// ─── Geometry Math Helpers ────────────────────────────────────────────────────

/** Flatten array of [x,y,z] triples into Float32Array */
function toFloat32(verts) {
  const f = new Float32Array(verts.length * 3);
  verts.forEach(([x, y, z], i) => { f[i*3]=x; f[i*3+1]=y; f[i*3+2]=z; });
  return f;
}

/** Flatten array of triangle index triples into Uint16Array */
function toUint16(tris) {
  const u = new Uint16Array(tris.length * 3);
  tris.forEach(([a, b, c], i) => { u[i*3]=a; u[i*3+1]=b; u[i*3+2]=c; });
  return u;
}

/**
 * Compute per-vertex normals, UV coordinates, and brand gradient vertex colors.
 * Returns { positions, normals, uvs, colors, indices }
 */
function computeVertexData(positions, triangles, W, H) {
  const outPos = [];
  const outNrm = [];
  const outUV  = [];
  const outCol = [];
  const outIdx = [];
  let vi = 0;

  for (const [a, b, c] of triangles) {
    const verts = [positions[a], positions[b], positions[c]];

    // Face normal
    const pa = verts[0], pb = verts[1], pc = verts[2];
    const e1 = [pb[0]-pa[0], pb[1]-pa[1], pb[2]-pa[2]];
    const e2 = [pc[0]-pa[0], pc[1]-pa[1], pc[2]-pa[2]];
    const nx = e1[1]*e2[2] - e1[2]*e2[1];
    const ny = e1[2]*e2[0] - e1[0]*e2[2];
    const nz = e1[0]*e2[1] - e1[1]*e2[0];
    const len = Math.sqrt(nx*nx + ny*ny + nz*nz) || 1;
    const n = [nx/len, ny/len, nz/len];

    for (const p of verts) {
      outPos.push(p);
      outNrm.push(n);

      // UV coordinates normalized across bounding box [-W, +W] and [-H, +H]
      const u = Math.max(0, Math.min(1, (p[0] + W) / (2 * W)));
      const v = Math.max(0, Math.min(1, (p[1] + H) / (2 * H)));
      outUV.push([u, v]);

      // Diagonal gradient parameter from top-left (#5B8DEF) to bottom-right (#9B6BF0)
      // Matching SVG brand logo definition: x1="0%" y1="0%" x2="100%" y2="100%"
      const t = Math.max(0, Math.min(1, 0.70 * u + 0.30 * (1 - v)));

      // Interpolate from Brand Blue (0.357, 0.553, 0.937) to Brand Violet (0.608, 0.420, 0.941)
      const r = 0.357 + t * (0.608 - 0.357);
      const g = 0.553 + t * (0.420 - 0.553);
      const b = 0.937 + t * (0.941 - 0.937);
      const alpha = 0.92;
      outCol.push([r, g, b, alpha]);
    }

    outIdx.push([vi, vi+1, vi+2]);
    vi += 3;
  }

  const fPos = new Float32Array(outPos.length * 3);
  outPos.forEach(([x, y, z], i) => { fPos[i*3]=x; fPos[i*3+1]=y; fPos[i*3+2]=z; });

  const fNrm = new Float32Array(outNrm.length * 3);
  outNrm.forEach(([x, y, z], i) => { fNrm[i*3]=x; fNrm[i*3+1]=y; fNrm[i*3+2]=z; });

  const fUV = new Float32Array(outUV.length * 2);
  outUV.forEach(([u, v], i) => { fUV[i*2]=u; fUV[i*2+1]=v; });

  const fCol = new Float32Array(outCol.length * 4);
  outCol.forEach(([r, g, b, a], i) => { fCol[i*4]=r; fCol[i*4+1]=g; fCol[i*4+2]=b; fCol[i*4+3]=a; });

  const uIdx = new Uint16Array(outIdx.length * 3);
  outIdx.forEach(([a, b, c], i) => { uIdx[i*3]=a; uIdx[i*3+1]=b; uIdx[i*3+2]=c; });

  return { positions: fPos, normals: fNrm, uvs: fUV, colors: fCol, indices: uIdx };
}

// ─── Bowtie Geometry Builder ──────────────────────────────────────────────────

/**
 * Build the bowtie/hourglass geometry.
 *
 * The shape: two triangular prisms (arrow-like cross-section) pointing inward,
 * tips meeting at the origin.
 *
 *      ←─────────  X  ─────────→
 *  [-W, H,±D]     [0,0,±D]     [W, H,±D]
 *       \            |           /
 *        \           |          /
 *  [-W,-H,±D]       |      [W,-H,±D]
 *              [tip at 0,0]
 *
 * Left arrow prism:  tip at (0,0), wide end at x=-W, spanning y=[-H,+H], z=[-D,+D]
 * Right arrow prism: tip at (0,0), wide end at x=+W, spanning y=[-H,+H], z=[-D,+D]
 *
 * @param {object} opts
 * @param {number} opts.W  half-width of the wide end
 * @param {number} opts.H  half-height of the prism
 * @param {number} opts.D  half-depth (extrusion)
 * @param {boolean} opts.bevel  add chamfer triangles at the center tips
 */
function buildBowtie({ W = 1.4, H = 0.9, D = 0.25, bevel = false } = {}) {
  // ── Vertex pool ──────────────────────────────────────────────────────────────
  // Left prism: tip at center, wide end at -W
  // Front face (z = +D)
  const L_TIP_F = [0,    0,  +D];   // 0
  const L_TOP_F = [-W,  +H,  +D];   // 1
  const L_BOT_F = [-W,  -H,  +D];   // 2
  // Back face (z = -D)
  const L_TIP_B = [0,    0,  -D];   // 3
  const L_TOP_B = [-W,  +H,  -D];   // 4
  const L_BOT_B = [-W,  -H,  -D];   // 5

  // Right prism: tip at center, wide end at +W
  const R_TIP_F = [0,    0,  +D];   // 6  (same world pos as L_TIP_F, separate for normals)
  const R_TOP_F = [+W,  +H,  +D];   // 7
  const R_BOT_F = [+W,  -H,  +D];   // 8
  const R_TIP_B = [0,    0,  -D];   // 9
  const R_TOP_B = [+W,  +H,  -D];   // 10
  const R_BOT_B = [+W,  -H,  -D];   // 11

  const positions = [
    L_TIP_F, L_TOP_F, L_BOT_F,  // 0-2
    L_TIP_B, L_TOP_B, L_BOT_B,  // 3-5
    R_TIP_F, R_TOP_F, R_BOT_F,  // 6-8
    R_TIP_B, R_TOP_B, R_BOT_B,  // 9-11
  ];

  // ── Triangle indices ──────────────────────────────────────────────────────
  const triangles = [
    // Left prism — front face (z+)
    [0, 1, 2],
    // Left prism — back face (z-, winding reversed for outward normal)
    [3, 5, 4],
    // Left prism — top edge quad (tip→top, front→back)
    [0, 3, 4],  [0, 4, 1],
    // Left prism — bottom edge quad
    [0, 2, 5],  [0, 5, 3],
    // Left prism — wide end quad (x=-W)
    [1, 4, 5],  [1, 5, 2],

    // Right prism — front face
    [6, 8, 7],
    // Right prism — back face
    [9, 10, 11],
    // Right prism — top edge quad
    [6, 7, 10],  [6, 10, 9],
    // Right prism — bottom edge quad
    [6, 9, 11],  [6, 11, 8],
    // Right prism — wide end quad (x=+W)
    [7, 8, 11],  [7, 11, 10],
  ];

  // ── Center bridge (thin quad connecting the two tips at the origin) ───────
  // Adds a small rectangular face at the center so the two prisms read as one
  // connected shape from the front rather than two floating tips.
  const BT = 0.04;  // bridge half-thickness
  // 4 extra verts for the center bridge cap:
  const CB_positions = [
    [0, +BT, +D],  // 12
    [0, -BT, +D],  // 13
    [0, +BT, -D],  // 14
    [0, -BT, -D],  // 15
  ];
  const cbOffset = positions.length;
  positions.push(...CB_positions);

  triangles.push(
    [cbOffset+0, cbOffset+1, cbOffset+3],
    [cbOffset+0, cbOffset+3, cbOffset+2],
  );

  // ── Bevel chamfer rings at each prism's center tip (hi-poly only) ─────────
  if (bevel) {
    const CR = 0.08;   // chamfer radius
    const angles = [0, Math.PI/2, Math.PI, 3*Math.PI/2, 2*Math.PI];  // 4 segments
    // Left tip bevel ring (front cap)
    const lvStart = positions.length;
    for (let i = 0; i < 4; i++) {
      const a0 = angles[i], a1 = angles[i+1];
      positions.push(
        [CR*Math.cos(a0), CR*Math.sin(a0), +D],
        [CR*Math.cos(a1), CR*Math.sin(a1), +D],
        [0, 0, +D + CR*0.5],
      );
      const b = positions.length - 3;
      triangles.push([b, b+1, b+2]);
    }
    // Right tip bevel ring (front cap)
    for (let i = 0; i < 4; i++) {
      const a0 = angles[i], a1 = angles[i+1];
      positions.push(
        [CR*Math.cos(a0), CR*Math.sin(a0), +D],
        [CR*Math.cos(a1), CR*Math.sin(a1), +D],
        [0, 0, +D + CR*0.5],
      );
      const b = positions.length - 3;
      triangles.push([b, b+1, b+2]);
    }
  }

  return computeVertexData(positions, triangles, W, H);
}

// ─── glTF 2.0 Binary (.glb) Writer ───────────────────────────────────────────

/**
 * Pack typed arrays into a .glb binary.
 * glTF 2.0 spec: https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html#glb-file-format-specification
 *
 * Structure:
 *   [12 B GLB header]
 *   [8+N  JSON chunk]
 *   [8+M  BIN  chunk]
 */
function buildGLB(positions, normals, uvs, colors, indices, label) {
  const posBytes = Buffer.from(positions.buffer, positions.byteOffset, positions.byteLength);
  const nrmBytes = Buffer.from(normals.buffer,   normals.byteOffset,   normals.byteLength);
  const uvBytes  = Buffer.from(uvs.buffer,       uvs.byteOffset,       uvs.byteLength);
  const colBytes = Buffer.from(colors.buffer,    colors.byteOffset,    colors.byteLength);
  const idxBytes = Buffer.from(indices.buffer,   indices.byteOffset,   indices.byteLength);

  // Pad binary views to 4-byte alignment (glTF requirement)
  const padTo4 = (n) => Math.ceil(n / 4) * 4;

  // BIN chunk layout: [positions | normals | uvs | colors | indices]
  const posOffset = 0;
  const posLen    = padTo4(posBytes.length);

  const nrmOffset = posOffset + posLen;
  const nrmLen    = padTo4(nrmBytes.length);

  const uvOffset  = nrmOffset + nrmLen;
  const uvLen     = padTo4(uvBytes.length);

  const colOffset = uvOffset + uvLen;
  const colLen    = padTo4(colBytes.length);

  const idxOffset = colOffset + colLen;
  const idxLen    = padTo4(idxBytes.length);

  const binLen    = idxOffset + idxLen;

  const binBuf = Buffer.alloc(binLen, 0);
  posBytes.copy(binBuf, posOffset);
  nrmBytes.copy(binBuf, nrmOffset);
  uvBytes.copy(binBuf,  uvOffset);
  colBytes.copy(binBuf, colOffset);
  idxBytes.copy(binBuf, idxOffset);

  const vertCount = positions.length / 3;    // 3 floats per vertex
  const triCount  = indices.length  / 3;     // 3 indices per triangle

  // Bounding box for accessor min/max (required by validators)
  let minX = Infinity, minY = Infinity, minZ = Infinity;
  let maxX = -Infinity, maxY = -Infinity, maxZ = -Infinity;
  for (let i = 0; i < positions.length; i += 3) {
    minX = Math.min(minX, positions[i]);   maxX = Math.max(maxX, positions[i]);
    minY = Math.min(minY, positions[i+1]); maxY = Math.max(maxY, positions[i+1]);
    minZ = Math.min(minZ, positions[i+2]); maxZ = Math.max(maxZ, positions[i+2]);
  }

  // glTF JSON descriptor
  const gltf = {
    asset: { version: '2.0', generator: 'softXchange-gltf-gen/1.1', copyright: 'softXchange' },
    scene: 0,
    scenes: [{ name: 'Scene', nodes: [0] }],
    nodes: [{
      name: 'softxchange_logo',
      mesh: 0,
    }],
    meshes: [{
      name: label,
      primitives: [{
        attributes: {
          POSITION: 0,
          NORMAL: 1,
          TEXCOORD_0: 2,
          COLOR_0: 3,
        },
        indices: 4,
        material: 0,
        mode: 4,  // TRIANGLES
      }],
    }],
    materials: [{
      name: 'SoftXchangeBrand',
      pbrMetallicRoughness: {
        baseColorFactor: [1.0, 1.0, 1.0, 1.0],  // Allows vertex colors to render at 100% full intensity
        metallicFactor:  0.05,
        roughnessFactor: 0.12,
      },
      emissiveFactor: [0.06, 0.06, 0.12],       // Subtle luminescence that complements the gradient
      alphaMode: 'BLEND',
      doubleSided: true,
      extras: {
        brand_gradient_start: '#5B8DEF',
        brand_gradient_end:   '#9B6BF0',
        transmission: 0.82,
        tier: label.includes('-lo') ? 'B' : 'A',
      },
    }],
    accessors: [
      // 0 — POSITION
      {
        bufferView: 0,
        byteOffset: 0,
        componentType: 5126,   // FLOAT
        count: vertCount,
        type: 'VEC3',
        min: [minX, minY, minZ],
        max: [maxX, maxY, maxZ],
      },
      // 1 — NORMAL
      {
        bufferView: 1,
        byteOffset: 0,
        componentType: 5126,   // FLOAT
        count: vertCount,
        type: 'VEC3',
      },
      // 2 — TEXCOORD_0
      {
        bufferView: 2,
        byteOffset: 0,
        componentType: 5126,   // FLOAT
        count: vertCount,
        type: 'VEC2',
        min: [0, 0],
        max: [1, 1],
      },
      // 3 — COLOR_0
      {
        bufferView: 3,
        byteOffset: 0,
        componentType: 5126,   // FLOAT
        count: vertCount,
        type: 'VEC4',
        min: [0.357, 0.420, 0.937, 0.92],
        max: [0.608, 0.553, 0.941, 0.92],
      },
      // 4 — indices
      {
        bufferView: 4,
        byteOffset: 0,
        componentType: 5123,   // UNSIGNED_SHORT
        count: triCount * 3,
        type: 'SCALAR',
      },
    ],
    bufferViews: [
      { buffer: 0, byteOffset: posOffset, byteLength: posBytes.length, target: 34962 }, // ARRAY_BUFFER
      { buffer: 0, byteOffset: nrmOffset, byteLength: nrmBytes.length, target: 34962 },
      { buffer: 0, byteOffset: uvOffset,  byteLength: uvBytes.length,  target: 34962 },
      { buffer: 0, byteOffset: colOffset, byteLength: colBytes.length, target: 34962 },
      { buffer: 0, byteOffset: idxOffset, byteLength: idxBytes.length, target: 34963 }, // ELEMENT_ARRAY_BUFFER
    ],
    buffers: [{ byteLength: binLen }],
  };

  const jsonStr    = JSON.stringify(gltf);
  const jsonBuf    = Buffer.from(jsonStr, 'utf8');
  // JSON chunk must be padded to 4 bytes with spaces (0x20)
  const jsonPadded = padTo4(jsonBuf.length);
  const jsonChunk  = Buffer.alloc(jsonPadded, 0x20);
  jsonBuf.copy(jsonChunk);

  // GLB: header (12) + JSON chunk header (8) + JSON data + BIN chunk header (8) + BIN data
  const totalLen = 12 + 8 + jsonPadded + 8 + binLen;
  const glb      = Buffer.alloc(totalLen);
  let off        = 0;

  // GLB header: magic, version, length
  glb.writeUInt32LE(0x46546C67, off); off += 4;  // 'glTF'
  glb.writeUInt32LE(2,          off); off += 4;  // version 2
  glb.writeUInt32LE(totalLen,   off); off += 4;

  // JSON chunk
  glb.writeUInt32LE(jsonPadded, off); off += 4;
  glb.writeUInt32LE(0x4E4F534A, off); off += 4;  // 'JSON'
  jsonChunk.copy(glb, off); off += jsonPadded;

  // BIN chunk
  glb.writeUInt32LE(binLen,     off); off += 4;
  glb.writeUInt32LE(0x004E4942, off); off += 4;  // 'BIN\0'
  binBuf.copy(glb, off);

  return glb;
}

// ─── Generate + Write ─────────────────────────────────────────────────────────

function generate(label, geoOpts, outFile) {
  const { positions, normals, uvs, colors, indices } = buildBowtie(geoOpts);
  const glb = buildGLB(positions, normals, uvs, colors, indices, label);
  const outPath = path.join(OUT_DIR, outFile);
  fs.writeFileSync(outPath, glb);

  const sizeKB = (glb.length / 1024).toFixed(1);
  const triCount = indices.length / 3;
  console.log(`✓  ${outFile.padEnd(16)} ${sizeKB.padStart(6)} KB  /  ${triCount} triangles`);
  return glb.length;
}

console.log('\n softXchange glTF Generator\n');
console.log(' file             size        tris');
console.log(' ─────────────────────────────────');

const hiSize = generate('softxchange-logo-hi', { W: 1.4, H: 0.9, D: 0.25, bevel: true },  'logo-hi.glb');
const loSize = generate('softxchange-logo-lo', { W: 1.4, H: 0.9, D: 0.20, bevel: false }, 'logo-lo.glb');

const LIMIT_KB = 80;
const LIMIT_BYTES = LIMIT_KB * 1024;
let fail = false;
if (hiSize > LIMIT_BYTES) { console.error(`\n✗  logo-hi.glb exceeds ${LIMIT_KB} KB limit`); fail = true; }
if (loSize > LIMIT_BYTES) { console.error(`\n✗  logo-lo.glb exceeds ${LIMIT_KB} KB limit`); fail = true; }

if (!fail) {
  console.log(`\n ✓ Both assets within ${LIMIT_KB} KB per-model limit`);
}
console.log('');

process.exit(fail ? 1 : 0);
