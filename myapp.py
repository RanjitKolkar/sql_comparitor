import streamlit as st
import hashlib
import difflib

# -------------------------------
# Utility Functions
# -------------------------------

def compute_hash(file, algo="sha256"):
    """Compute hash for uploaded file (Streamlit UploadedFile)."""
    h = hashlib.new(algo)
    file.seek(0)
    while chunk := file.read(4096):
        h.update(chunk)
    file.seek(0)
    return h.hexdigest()

def show_diff(text1, text2):
    """Return an HTML diff view of two texts."""
    diff = difflib.HtmlDiff(wrapcolumn=80)
    return diff.make_table(
        text1.splitlines(),
        text2.splitlines(),
        fromdesc="Original File",
        todesc="Compared File",
        context=True,
        numlines=5
    )

# -------------------------------
# Streamlit UI
# -------------------------------

st.set_page_config(page_title="SQL Hash & Diff Checker", layout="wide")
st.title("🔍 SQL File Hash & Difference Checker")

st.write("""
Upload **two SQL files** to verify integrity and visualize differences.  
The app computes **MD5** and **SHA256** hashes, then displays any changes between the files.
""")

col1, col2 = st.columns(2)

with col1:
    file1 = st.file_uploader("Upload Original SQL File", type=["sql"], key="file1")
with col2:
    file2 = st.file_uploader("Upload Tampered SQL File", type=["sql"], key="file2")

if file1 and file2:
    st.divider()
    st.subheader("🔐 File Hashes")

    # Compute hashes
    md5_1 = compute_hash(file1, "md5")
    md5_2 = compute_hash(file2, "md5")
    sha1_1 = compute_hash(file1, "sha256")
    sha1_2 = compute_hash(file2, "sha256")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"**{file1.name}**")
        st.code(f"MD5:    {md5_1}\nSHA256: {sha1_1}")
    with col2:
        st.markdown(f"**{file2.name}**")
        st.code(f"MD5:    {md5_2}\nSHA256: {sha1_2}")

    # Compare hashes
    if sha1_1 == sha1_2:
        st.success("✅ Files are identical. No tampering detected.")
    else:
        st.error("⚠️ Files differ! Possible tampering detected.")

    # Show differences
    st.divider()
    st.subheader("📜 File Differences")

    file1.seek(0)
    file2.seek(0)
    text1 = file1.read().decode("utf-8", errors="ignore")
    text2 = file2.read().decode("utf-8", errors="ignore")

    html_diff = show_diff(text1, text2)
    st.components.v1.html(html_diff, height=600, scrolling=True)

else:
    st.info("⬆️ Please upload both SQL files to begin comparison.")
