def gnuas_escape_label(label_name: str) -> str:
    # if "?" in label_name:
    #     return f'"{label_name}"'
    # else:
    #     return label_name

    # label_name = label_name.replace("?", "\\?")
    # label_name = label_name.replace("@", "\\@")

    # TODO: what is going on here (calling conventions?), and is it always correct to prepend the underscore?
    return "_" + label_name
