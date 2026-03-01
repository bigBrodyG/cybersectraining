def fix_O():
    with open("O_matrix.txt", "r") as f:
        lines = f.readlines()
    
    O_mat = []
    for line in lines:
        if line.strip():
            O_mat.append([int(x) for x in line.strip().split(",")])
            
    # O_true[j][c] = O_matrix[j ^ 1][c ^ 1]
    O_true = [[0]*18 for _ in range(46)]
    for j in range(46):
        for c in range(18):
            O_true[j][c] = O_mat[j ^ 1][c ^ 1]
            
    with open("O_matrix_fixed.txt", "w") as f:
        for row in O_true:
            f.write(",".join(map(str, row)) + "
")

if __name__ == "__main__":
    fix_O()
    print("Fixed O matrix saved to O_matrix_fixed.txt")
