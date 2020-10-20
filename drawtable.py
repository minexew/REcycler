def lpad(str, width):
    return ' ' * (width - len(str)) + str

def rpad(str, width):
    return str + ' ' * (width - len(str))

class Table:
    def __init__(self, cols, file):
        self.cols = [dict(title=title, width=max(width, len(title)), format=format) for title, width, format in cols]

        print(file=file)

        header = ' | '.join([rpad(col['title'], col['width']) for col in self.cols])
        print(header, file=file)
        print('=' * len(header), file=file)

        self.file = file

    def row(self, *args):
        row = ' | '.join([lpad(col['format'] % args[i], col['width']) for i, col in enumerate(self.cols)])
        print(row, file=self.file)
