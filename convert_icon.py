from svglib.svglib import svg2rlg
from reportlab.graphics import renderPM
from PIL import Image
import os

print("Rendering SVG to PNG...")
drawing = svg2rlg("assets/app_icon.svg")
renderPM.drawToFile(drawing, "assets/icon.png", fmt="PNG")

print("Converting PNG to ICO...")
img = Image.open("assets/icon.png")
# Resize for multiple icon sizes
icon_sizes = [(16,16), (32, 32), (48, 48), (64,64), (120, 120)]
img.save("assets/icon.ico", format="ICO", sizes=icon_sizes)

print("Cleaning up...")
if os.path.exists("assets/icon.png"):
    os.remove("assets/icon.png")
print("Done!")
