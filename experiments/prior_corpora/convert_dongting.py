import zipfile, io, re, numpy as np

# 1) build syscall number -> name map from syscall_64.tbl
num2name = {}
for line in open("/root/dongting/syscall_64.tbl"):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    parts = line.split()
    # format: <number> <abi> <name> <entry>
    if len(parts) >= 3 and parts[0].isdigit():
        num2name[int(parts[0])] = parts[2]
print("syscall map entries:", len(num2name), "e.g. 0->", num2name.get(0), "60->", num2name.get(60))

z = zipfile.ZipFile("/root/dongting/npz.zip")

def load_seqs(npz_name, label):
    d = np.load(io.BytesIO(z.read(npz_name)), allow_pickle=True)
    splits = d["arr_0"]   # list of 4 splits, each a list of int-seq arrays
    seqs = []
    for sub in splits:
        for s in sub:
            names = [num2name.get(int(x), f"sys_{int(x)}") for x in s]
            seqs.append(" ".join(names))
    return seqs, [label]*len(seqs)

nseq, ny = load_seqs("npz/DT-Normal.npz", 0)
aseq, ay = load_seqs("npz/DT-Abnormal.npz", 1)
print("normal seqs:", len(nseq), "attack seqs:", len(aseq))

seqs = np.array(nseq + aseq, dtype=object)
y = np.array(ny + ay, dtype=np.int8)
print("total:", len(seqs), "| sample normal:", nseq[0][:80])
print("sample attack:", aseq[0][:80])

# save in the same format as feature_cache/*.npz (seqs + y)
np.savez_compressed("/root/dongting/DongTing.npz", seqs=seqs, y=y)
import os
print("saved DongTing.npz size MB:", round(os.path.getsize("/root/dongting/DongTing.npz")/1e6,1))
