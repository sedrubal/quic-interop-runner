#!/usr/bin/env python

"""
#Tango Colors module

This module provides tango colors in several model.

[tango palette](http://tango.freedesktop.org/Tango_Icon_Theme_Guidelines#Color_Palette)
"""

import re
import unittest

import matplotlib.colors as mplcolors
import numpy as np

__license__ = "GPL-2.0 License"
__author__ = "Germain Salvato Vallverdu <germain.vallverdu@gmail.com>"
__source__ = "https://github.com/gVallverdu/tango-colors/"

html_patt = re.compile("#(\d|[a-fA-F]){6}")

TANGO_HTML_COLORS = {
    "butter1": "#fce94f",
    "butter2": "#edd400",
    "butter3": "#c4a000",
    "orange1": "#fcaf3e",
    "orange2": "#f57900",
    "orange3": "#ce5c00",
    "chocolate1": "#e9b96e",
    "chocolate2": "#c17d11",
    "chocolate3": "#8f5902",
    "chameleon1": "#8ae234",
    "chameleon2": "#73d216",
    "chameleon3": "#4e9a06",
    "skyblue1": "#729fcf",
    "skyblue2": "#3465a4",
    "skyblue3": "#204a87",
    "plum1": "#ad7fa8",
    "plum2": "#75507b",
    "plum3": "#5c3566",
    "scarletred1": "#ef2929",
    "scarletred2": "#cc0000",
    "scarletred3": "#a40000",
    "aluminium1": "#eeeeec",
    "aluminium2": "#d3d7cf",
    "aluminium3": "#babdb6",
    "aluminium4": "#888a85",
    "aluminium5": "#555753",
    "aluminium6": "#2e3436",
}

TANGO_HTML_COLORS["LightButter"] = TANGO_HTML_COLORS["butter1"]
TANGO_HTML_COLORS["Butter"] = TANGO_HTML_COLORS["butter2"]
TANGO_HTML_COLORS["DarkButter"] = TANGO_HTML_COLORS["butter3"]
TANGO_HTML_COLORS["LightOrange"] = TANGO_HTML_COLORS["orange1"]
TANGO_HTML_COLORS["Orange"] = TANGO_HTML_COLORS["orange2"]
TANGO_HTML_COLORS["DarkOrange"] = TANGO_HTML_COLORS["orange3"]
TANGO_HTML_COLORS["LightChocolate"] = TANGO_HTML_COLORS["chocolate1"]
TANGO_HTML_COLORS["Chocolate"] = TANGO_HTML_COLORS["chocolate2"]
TANGO_HTML_COLORS["DarkChocolate"] = TANGO_HTML_COLORS["chocolate3"]
TANGO_HTML_COLORS["LightChameleon"] = TANGO_HTML_COLORS["chameleon1"]
TANGO_HTML_COLORS["Chameleon"] = TANGO_HTML_COLORS["chameleon2"]
TANGO_HTML_COLORS["DarkChameleon"] = TANGO_HTML_COLORS["chameleon3"]
TANGO_HTML_COLORS["LightSkyBlue"] = TANGO_HTML_COLORS["skyblue1"]
TANGO_HTML_COLORS["SkyBlue"] = TANGO_HTML_COLORS["skyblue2"]
TANGO_HTML_COLORS["DarkSkyBlue"] = TANGO_HTML_COLORS["skyblue3"]
TANGO_HTML_COLORS["LightPlum"] = TANGO_HTML_COLORS["plum1"]
TANGO_HTML_COLORS["Plum"] = TANGO_HTML_COLORS["plum2"]
TANGO_HTML_COLORS["DarkPlum"] = TANGO_HTML_COLORS["plum3"]
TANGO_HTML_COLORS["LightScarletRed"] = TANGO_HTML_COLORS["scarletred1"]
TANGO_HTML_COLORS["ScarletRed"] = TANGO_HTML_COLORS["scarletred2"]
TANGO_HTML_COLORS["DarkScarletRed"] = TANGO_HTML_COLORS["scarletred3"]


class Tango:
    """
    This class store tango colors in different model.
    """

    available_models = ("HTML", "RGB", "rgb", "HSV", "hsv")

    def __init__(self, model="HTML"):
        """init the class and define the model"""

        if model in Tango.available_models:
            self.model = model
        else:
            raise ValueError("model {} not available".format(model))

    def HTML_to_color(self, c):
        """Return color in a given model."""

        if not html_patt.match(c):
            raise ValueError("color {} is not a valid HTML color".format(c))

        if self.model == "HTML":
            color = c
        elif self.model == "rgb":
            color = mplcolors.hex2color(c)
        elif self.model == "RGB":
            color = tuple(int(val * 255) for val in mplcolors.hex2color(c))
        elif self.model == "hsv":
            rgb = mplcolors.hex2color(c)
            color = mplcolors.rgb_to_hsv(np.array(rgb).reshape(1, 1, 3))
            color = tuple(color.reshape(3))
        elif self.model == "HSV":
            rgb = mplcolors.hex2color(c)
            color = mplcolors.rgb_to_hsv(np.array(rgb).reshape(1, 1, 3))
            h, s, v = color.reshape(3)
            color = (round(h * 360), round(s * 100), round(v * 100))

        return color

    @property
    def butter1(self):
        """butter1"""

        return self.HTML_to_color(TANGO_HTML_COLORS["butter1"])

    @property
    def LightButter(self):
        """Light Butter"""

        return self.butter1

    @property
    def butter2(self):
        """butter2"""

        return self.HTML_to_color(TANGO_HTML_COLORS["butter2"])

    @property
    def Butter(self):
        """Butter"""

        return self.butter2

    @property
    def butter3(self):
        """butter3"""

        return self.HTML_to_color(TANGO_HTML_COLORS["butter3"])

    @property
    def DarkButter(self):
        """Dark Butter"""

        return self.butter3

    @property
    def orange1(self):
        """orange1"""

        return self.HTML_to_color(TANGO_HTML_COLORS["orange1"])

    @property
    def LightOrange(self):
        """Light Orange"""

        return self.orange1

    @property
    def orange2(self):
        """orange2"""

        return self.HTML_to_color(TANGO_HTML_COLORS["orange2"])

    @property
    def Orange(self):
        """Orange"""

        return self.orange2

    @property
    def orange3(self):
        """orange3"""

        return self.HTML_to_color(TANGO_HTML_COLORS["orange3"])

    @property
    def DarkOrange(self):
        """Dark Orange"""

        return self.orange3

    @property
    def chocolate1(self):
        """chocolate1"""

        return self.HTML_to_color(TANGO_HTML_COLORS["chocolate1"])

    @property
    def LightChocolate(self):
        """Dark Chocolate"""

        return self.chocolate1

    @property
    def chocolate2(self):
        """chocolate2"""

        return self.HTML_to_color(TANGO_HTML_COLORS["chocolate2"])

    @property
    def Chocolate(self):
        """Chocolate"""

        return self.chocolate2

    @property
    def chocolate3(self):
        """chocolate3"""

        return self.HTML_to_color(TANGO_HTML_COLORS["chocolate3"])

    @property
    def DarkChocolate(self):
        """Dark Chocolate"""

        return self.chocolate3

    @property
    def chameleon1(self):
        """chameleon1"""

        return self.HTML_to_color(TANGO_HTML_COLORS["chameleon1"])

    @property
    def LightChameleon(self):
        """Light Chameleon"""

        return self.chameleon1

    @property
    def chameleon2(self):
        """chameleon2"""

        return self.HTML_to_color(TANGO_HTML_COLORS["chameleon2"])

    @property
    def Chameleon(self):
        """Chameleon"""

        return self.chameleon2

    @property
    def chameleon3(self):
        """chameleon3"""

        return self.HTML_to_color(TANGO_HTML_COLORS["chameleon3"])

    @property
    def DarkChameleon(self):
        """Dark Chameleon"""

        return self.chameleon3

    @property
    def skyblue1(self):
        """skyblue1"""

        return self.HTML_to_color(TANGO_HTML_COLORS["skyblue1"])

    @property
    def LightSkyBlue(self):
        """Light Sky Blue"""

        return self.skyblue1

    @property
    def skyblue2(self):
        """skyblue2"""

        return self.HTML_to_color(TANGO_HTML_COLORS["skyblue2"])

    @property
    def SkyBlue(self):
        """Sky Blue"""

        return self.skyblue2

    @property
    def skyblue3(self):
        """skyblue3"""

        return self.HTML_to_color(TANGO_HTML_COLORS["skyblue3"])

    @property
    def DarkSkyBlue(self):
        """Dark Sky Blue"""

        return self.skyblue3

    @property
    def plum1(self):
        """plum1"""

        return self.HTML_to_color(TANGO_HTML_COLORS["plum1"])

    @property
    def LightPlum(self):
        """Light Plum"""

        return self.plum1

    @property
    def plum2(self):
        """plum2"""

        return self.HTML_to_color(TANGO_HTML_COLORS["plum2"])

    @property
    def Plum(self):
        """Plum"""

        return self.plum2

    @property
    def plum3(self):
        """plum3"""

        return self.HTML_to_color(TANGO_HTML_COLORS["plum3"])

    @property
    def DarkPlum(self):
        """Dark Plum"""

        return self.plum3

    @property
    def scarletred1(self):
        """scarletred1"""

        return self.HTML_to_color(TANGO_HTML_COLORS["scarletred1"])

    @property
    def LightScarletRed(self):
        """Light Scarlet Red"""

        return self.scarletred1

    @property
    def scarletred2(self):
        """scarletred2"""

        return self.HTML_to_color(TANGO_HTML_COLORS["scarletred2"])

    @property
    def ScarletRed(self):
        """Scarlet Red"""

        return self.scarletred2

    @property
    def scarletred3(self):
        """scarletred3"""

        return self.HTML_to_color(TANGO_HTML_COLORS["scarletred3"])

    @property
    def DarkScarletRed(self):
        """Dark Scarlet Red"""

        return self.scarletred3

    @property
    def aluminium1(self):
        """aluminium1"""

        return self.HTML_to_color(TANGO_HTML_COLORS["aluminium1"])

    @property
    def aluminium2(self):
        """aluminium2"""

        return self.HTML_to_color(TANGO_HTML_COLORS["aluminium2"])

    @property
    def aluminium3(self):
        """aluminium3"""

        return self.HTML_to_color(TANGO_HTML_COLORS["aluminium3"])

    @property
    def aluminium4(self):
        """aluminium4"""

        return self.HTML_to_color(TANGO_HTML_COLORS["aluminium4"])

    @property
    def aluminium5(self):
        """aluminium5"""

        return self.HTML_to_color(TANGO_HTML_COLORS["aluminium5"])

    @property
    def aluminium6(self):
        """aluminium6"""

        return self.HTML_to_color(TANGO_HTML_COLORS["aluminium6"])


class TangoTest(unittest.TestCase):
    def test_conversion(self):
        self.assertEqual(Tango("HTML").orange2, "#f57900")
        self.assertEqual(Tango().orange2, "#f57900")
        oRGB = Tango("RGB").orange2
        self.assertEqual(oRGB[0], 245)
        self.assertEqual(oRGB[1], 121)
        self.assertEqual(oRGB[2], 0)
        oRGB = Tango("rgb").orange2
        self.assertAlmostEqual(oRGB[0], 0.96078431)
        self.assertAlmostEqual(oRGB[1], 0.47450980)
        self.assertAlmostEqual(oRGB[2], 0.0)
        oHSV = Tango("HSV").orange2
        self.assertEqual(oHSV[0], 30)
        self.assertEqual(oHSV[1], 100)
        self.assertEqual(oHSV[2], 96)


if __name__ == "__main__":
    unittest.main()
