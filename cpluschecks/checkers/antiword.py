from checkers.base_checker import BaseChecker


class Antiword(BaseChecker):
    VENDOR = "antiword"
    PRODUCT = "antiword"
    LINK_SOURCE = "https://github.com/grobian/antiword.git"
    CONTAINS_PATTERNS = [
        r"generic\s+include\s+file\s+for\s+project\s+['\"]antiword['\"]",
        r"Copyright\s*\(C\)\s*[0-9]{4}[-–][0-9]{4}\s*A\.J\.\s*van\s+Os;\s*Released\s+under\s+(?:GNU\s+)?GPL",
        r"The\s+main\s+program\s+of\s+['\"]antiword['\"]",
    ]
    VERSION_PATTERNS = [
        r'#define\s+VERSIONSTRING\s+"([0-9]+\.[0-9]+)(?:[^"]*)"',
    ]
    VERSION_GUARD_PATTERNS = [
        r'#define\s+PURPOSESTRING\s+"Display\s+MS-Word\s+files"',
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)version\.h$",
    ]
