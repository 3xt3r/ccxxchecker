from checkers.base_checker import BaseChecker


class Mongoose(BaseChecker):
    VENDOR = "cesanta"
    PRODUCT = "mongoose"
    LINK_SOURCE = "https://github.com/cesanta/mongoose.git"
    CONTAINS_PATTERNS = [r"Sergey\s+Lyubka"]
    VERSION_PATTERNS = [r'#\s*define\s+(?:MONGOOSE_VERSION|MG_VERSION)\s+"([\d\.]+)"']
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)mongoose\.h$",
        r"(^|/)mg\.h$",
    ]
