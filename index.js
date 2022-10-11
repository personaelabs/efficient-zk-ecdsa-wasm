import pcg from "./pkg/rust_elliptic_curve.js";

const main = () => {
    console.log(pcg)
    const point_row = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    const result = pcg.compute_powers(point_row);
}
