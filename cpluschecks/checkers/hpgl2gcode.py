from checkers.base_checker import BaseChecker


class Hpgl2gcode(BaseChecker):
    VENDOR = "roboterbastler"
    PRODUCT = "hpgl2gcode"
    LINK_SOURCE = "https://github.com/Roboterbastler/hpgl2gcode"
    CONTAINS_PATTERNS = [
        r"HP-GL to GCode",
        r"HP-GL.*GCode",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)(README|LICENSE|\.gitignore)$",
        r"(^|/)HP-GL-to-GCode\.pro$",
    ]
    VERSION_PATTERNS = [
        r"HP-GL to GCode.*v?([0-9]+(?:\.[0-9]+){1,3})",
    ]
