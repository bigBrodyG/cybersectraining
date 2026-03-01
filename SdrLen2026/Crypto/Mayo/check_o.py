with open("O_matrix.txt") as f:
    lines = f.readlines()
print("Number of rows:", len(lines))
if len(lines) > 0:
    print("Row 0 length:", len(lines[0].strip().split(',')))
