"""Generate WinnyTool .ico file - shield with W logo"""
import struct, os

os.makedirs('assets', exist_ok=True)

size = 32
pixels = []
bg = (0, 0, 0, 0)
dark = (26, 26, 46, 255)       # #1a1a2e
mid = (22, 33, 62, 255)        # #16213e
accent = (233, 69, 96, 255)    # #e94560
white = (255, 255, 255, 255)

for y in range(size):
    row = []
    for x in range(size):
        in_shield = False
        if 2 <= y <= 19 and 4 <= x <= 27:
            in_shield = True
        elif 20 <= y <= 29:
            p = (y - 20) / 10.0
            left = 4 + int(p * 12)
            right = 27 - int(p * 12)
            if left <= x <= right:
                in_shield = True

        if not in_shield:
            row.append(bg)
            continue

        # Border
        is_border = False
        if y == 2 and 4 <= x <= 27:
            is_border = True
        elif 2 <= y <= 19 and (x == 4 or x == 27):
            is_border = True
        elif y >= 20:
            p = (y - 20) / 10.0
            left = 4 + int(p * 12)
            right = 27 - int(p * 12)
            if x == left or x == right or y == 29:
                is_border = True

        if is_border:
            row.append(accent)
            continue

        # Top accent bar
        if 3 <= y <= 6:
            row.append(accent)
            continue

        # Draw W letter
        draw_w = False
        if 9 <= y <= 22:
            wy = y - 9
            # Left down-stroke
            lx = 8 + wy // 3
            if lx <= x <= lx + 1:
                draw_w = True
            # Right down-stroke
            rx = 23 - wy // 3
            if rx <= x <= rx + 1:
                draw_w = True
            # Inner left up-stroke
            if wy >= 4:
                ilx = 14 - (wy - 4) // 3
                if ilx <= x <= ilx + 1:
                    draw_w = True
            # Inner right up-stroke
            if wy >= 4:
                irx = 17 + (wy - 4) // 3
                if irx <= x <= irx + 1:
                    draw_w = True
            # Bottom V connections
            if 11 <= wy <= 13:
                if 12 <= x <= 14 or 17 <= x <= 19:
                    draw_w = True

        if draw_w:
            row.append(white)
        elif y < size // 2:
            row.append(dark)
        else:
            row.append(mid)

    pixels.append(row)

# ICO uses bottom-up
pixels.reverse()

# Build BGRA bitmap
bmp_data = bytearray()
for row in pixels:
    for r, g, b, a in row:
        bmp_data.extend([b, g, r, a])

and_mask = bytearray(size * 4)

bmp_header = struct.pack('<IiiHHIIiiII',
    40, size, size * 2, 1, 32, 0,
    len(bmp_data) + len(and_mask), 0, 0, 0, 0)

image_data = bmp_header + bytes(bmp_data) + bytes(and_mask)
ico_header = struct.pack('<HHH', 0, 1, 1)
ico_entry = struct.pack('<BBBBHHII', size, size, 0, 0, 1, 32, len(image_data), 22)

with open('assets/winnytool.ico', 'wb') as f:
    f.write(ico_header)
    f.write(ico_entry)
    f.write(image_data)

print(f"Created assets/winnytool.ico ({os.path.getsize('assets/winnytool.ico')} bytes)")
