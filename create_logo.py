"""Generate WinnyTool logo as base64-encoded PNG for embedding in app and reports."""
import struct, zlib, os, base64

def create_png(width, height, pixels):
    """Create a PNG file from RGBA pixel data."""
    def chunk(chunk_type, data):
        c = chunk_type + data
        crc = struct.pack('>I', zlib.crc32(c) & 0xffffffff)
        return struct.pack('>I', len(data)) + c + crc

    # PNG signature
    sig = b'\x89PNG\r\n\x1a\n'

    # IHDR
    ihdr = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)  # 8-bit RGBA

    # IDAT - pixel data with filter byte
    raw = bytearray()
    for y in range(height):
        raw.append(0)  # filter: none
        for x in range(width):
            r, g, b, a = pixels[y][x]
            raw.extend([r, g, b, a])

    compressed = zlib.compress(bytes(raw), 9)

    return sig + chunk(b'IHDR', ihdr) + chunk(b'IDAT', compressed) + chunk(b'IEND', b'')


def draw_shield_logo(size=64):
    """Draw a shield with W logo at given size."""
    pixels = []

    bg = (0, 0, 0, 0)
    dark = (26, 26, 46, 255)
    mid = (22, 33, 62, 255)
    accent = (233, 69, 96, 255)
    white = (255, 255, 255, 255)
    light_accent = (240, 120, 140, 255)

    s = size
    cx = s // 2

    for y in range(s):
        row = []
        ny = y / s  # normalized 0-1

        for x in range(s):
            nx = x / s

            # Shield shape
            in_shield = False
            shield_left = 0.1
            shield_right = 0.9
            shield_top = 0.05
            shield_body_bottom = 0.6
            shield_point_y = 0.92

            if ny >= shield_top and ny <= shield_body_bottom:
                if nx >= shield_left and nx <= shield_right:
                    in_shield = True
            elif ny > shield_body_bottom and ny <= shield_point_y:
                progress = (ny - shield_body_bottom) / (shield_point_y - shield_body_bottom)
                left = shield_left + progress * (0.5 - shield_left)
                right = shield_right - progress * (shield_right - 0.5)
                if nx >= left and nx <= right:
                    in_shield = True

            if not in_shield:
                row.append(bg)
                continue

            # Border detection (2px equivalent)
            border_width = 2.5 / s
            is_border = False

            if ny < shield_top + border_width or abs(ny - shield_body_bottom) < border_width * 0.5:
                pass  # skip top/mid borders for cleaner look

            if ny >= shield_top and ny <= shield_body_bottom:
                if nx < shield_left + border_width or nx > shield_right - border_width:
                    is_border = True
                if ny < shield_top + border_width:
                    is_border = True
            elif ny > shield_body_bottom:
                progress = (ny - shield_body_bottom) / (shield_point_y - shield_body_bottom)
                left = shield_left + progress * (0.5 - shield_left)
                right = shield_right - progress * (shield_right - 0.5)
                if nx < left + border_width or nx > right - border_width:
                    is_border = True
                if ny > shield_point_y - border_width * 2:
                    is_border = True

            if is_border:
                row.append(accent)
                continue

            # Top accent banner
            banner_top = shield_top + border_width
            banner_bottom = 0.2
            if ny >= banner_top and ny <= banner_bottom:
                row.append(accent)
                continue

            # Draw W
            draw_w = False
            w_top = 0.28
            w_bottom = 0.78
            w_left = 0.2
            w_right = 0.8

            if ny >= w_top and ny <= w_bottom:
                wy = (ny - w_top) / (w_bottom - w_top)  # 0-1 within W
                stroke = 3.0 / s  # stroke width

                # Left outer stroke: goes from top-left to bottom-center-left
                lx = w_left + wy * 0.15
                if abs(nx - lx) < stroke:
                    draw_w = True

                # Right outer stroke: goes from top-right to bottom-center-right
                rx = w_right - wy * 0.15
                if abs(nx - rx) < stroke:
                    draw_w = True

                # Inner left stroke: goes from mid down to center-left valley
                if wy >= 0.25:
                    inner_wy = (wy - 0.25) / 0.75
                    ilx = 0.42 - inner_wy * 0.1
                    if abs(nx - ilx) < stroke:
                        draw_w = True

                # Inner right stroke: goes from mid down to center-right valley
                if wy >= 0.25:
                    inner_wy = (wy - 0.25) / 0.75
                    irx = 0.58 + inner_wy * 0.1
                    if abs(nx - irx) < stroke:
                        draw_w = True

                # Center peak
                if wy >= 0.15 and wy <= 0.55:
                    peak_wy = (wy - 0.15) / 0.4
                    # Left peak going up
                    plx = 0.42 + (1 - peak_wy) * 0.08
                    if abs(nx - plx) < stroke:
                        draw_w = True
                    # Right peak going up
                    prx = 0.58 - (1 - peak_wy) * 0.08
                    if abs(nx - prx) < stroke:
                        draw_w = True

            if draw_w:
                row.append(white)
            elif ny < 0.5:
                row.append(dark)
            else:
                row.append(mid)

        pixels.append(row)

    return pixels


# Generate multiple sizes
for sz, name in [(64, 'logo_64'), (128, 'logo_128')]:
    pixels = draw_shield_logo(sz)
    png_data = create_png(sz, sz, pixels)

    # Save PNG
    os.makedirs('assets', exist_ok=True)
    with open(f'assets/{name}.png', 'wb') as f:
        f.write(png_data)
    print(f"Created assets/{name}.png ({len(png_data)} bytes)")

# Generate base64 for embedding
with open('assets/logo_64.png', 'rb') as f:
    b64 = base64.b64encode(f.read()).decode()

# Write the base64 string to a file for easy copy
with open('assets/logo_base64.txt', 'w') as f:
    f.write(b64)

print(f"\nBase64 logo saved to assets/logo_base64.txt ({len(b64)} chars)")
print("Copy this into winnytool.py as LOGO_BASE64 constant")
