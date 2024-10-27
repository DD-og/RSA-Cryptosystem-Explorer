import streamlit as st
import random
import math
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import gmpy2
import json
import plotly.graph_objects as go
import pandas as pd
from hashlib import sha256
from datetime import datetime
import altair as alt

# At the very beginning of the script, after the imports
if 'key_stats' not in st.session_state:
    st.session_state.key_stats = []

def is_prime_miller_rabin(n, k=10):
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << bits - 1) | 1
        if is_prime_miller_rabin(p):
            return p

def generate_keypair_with_progress(key_size, progress_bar):
    bits = key_size // 2
    start_time = time.time()
    
    progress_bar.progress(0.1)
    st.write("Generating prime p...")
    p = generate_prime(bits)
    
    progress_bar.progress(0.4)
    st.write("Generating prime q...")
    q = generate_prime(bits)
    
    progress_bar.progress(0.6)
    st.write("Computing n and φ(n)...")
    n = p * q
    phi = (p - 1) * (q - 1)
    
    progress_bar.progress(0.8)
    st.write("Selecting public exponent e...")
    e = 65537  # Commonly used value for e
    
    progress_bar.progress(0.9)
    st.write("Computing private exponent d...")
    d = pow(e, -1, phi)
    
    progress_bar.progress(1.0)
    
    generation_time = time.time() - start_time
    return ((e, n), (d, n)), generation_time

def pad_message(message, block_size):
    if isinstance(message, str):
        message = message.encode('utf-8')
    padding = block_size - len(message) % block_size
    return message + bytes([padding] * padding)

def unpad_message(padded_message):
    padding = padded_message[-1]
    return padded_message[:-padding]

def encrypt(public_key, plaintext):
    e, n = public_key
    block_size = (n.bit_length() + 7) // 8 - 1
    padded = pad_message(plaintext, block_size)
    cipher = [pow(int.from_bytes(padded[i:i+block_size], 'big'), e, n)
              for i in range(0, len(padded), block_size)]
    return cipher

def decrypt(private_key, ciphertext):
    d, n = private_key
    block_size = (n.bit_length() + 7) // 8
    decrypted = b''.join([pow(c, d, n).to_bytes(block_size, 'big').lstrip(b'\x00')
                          for c in ciphertext])
    return unpad_message(decrypted).decode('utf-8')

def encrypt_file_with_progress(public_key, file_contents, progress_bar):
    e, n = public_key
    block_size = (n.bit_length() + 7) // 8 - 1
    padded = pad_message(file_contents, block_size)
    total_blocks = len(padded) // block_size
    
    cipher = []
    for i in range(0, len(padded), block_size):
        block = padded[i:i+block_size]
        cipher.append(pow(int.from_bytes(block, 'big'), e, n))
        progress_bar.progress((i + block_size) / len(padded))
    
    return cipher

def decrypt_file_with_progress(private_key, ciphertext, progress_bar):
    d, n = private_key
    block_size = (n.bit_length() + 7) // 8
    decrypted = b''
    total_blocks = len(ciphertext)
    
    for i, c in enumerate(ciphertext):
        decrypted += pow(c, d, n).to_bytes(block_size, 'big').lstrip(b'\x00')
        progress_bar.progress((i + 1) / total_blocks)
    
    return unpad_message(decrypted)

def get_key_strength(key_size):
    if key_size < 2048:
        return "Weak", "red"
    elif key_size < 3072:
        return "Moderate", "orange"
    else:
        return "Strong", "green"

def visualize_rsa_process(p, q, e, d, m):
    n = p * q
    phi = (p - 1) * (q - 1)
    c = pow(m, e, n)
    m_decrypted = pow(c, d, n)
    
    # Create a more interesting visualization with multiple subplots
    fig = go.Figure()
    
    # Key Generation Phase
    fig.add_trace(go.Scatter(
        x=[1, 2, 3, 4, 5],
        y=[p, q, n, phi, e],
        mode='markers+lines+text',
        name='Key Generation',
        text=[f'p={p}', f'q={q}', f'n={n}', f'φ(n)={phi}', f'e={e}'],
        textposition="top center",
        line=dict(color='blue', width=2),
        marker=dict(size=12, symbol='diamond')
    ))
    
    # Encryption Phase
    fig.add_trace(go.Scatter(
        x=[6, 7],
        y=[m, c],
        mode='markers+lines+text',
        name='Encryption',
        text=[f'Message={m}', f'Cipher={c}'],
        textposition="top center",
        line=dict(color='red', width=2),
        marker=dict(size=12, symbol='star')
    ))
    
    # Decryption Phase
    fig.add_trace(go.Scatter(
        x=[8, 9],
        y=[d, m_decrypted],
        mode='markers+lines+text',
        name='Decryption',
        text=[f'd={d}', f'Decrypted={m_decrypted}'],
        textposition="top center",
        line=dict(color='green', width=2),
        marker=dict(size=12, symbol='circle')
    ))
    
    # Add arrows and annotations to show the flow
    fig.add_annotation(
        x=3, y=n,
        text="n = p × q",
        showarrow=True,
        arrowhead=2
    )
    
    fig.add_annotation(
        x=6.5, y=(m + c)/2,
        text="c ≡ m^e mod n",
        showarrow=True,
        arrowhead=2
    )
    
    fig.add_annotation(
        x=8.5, y=(d + m_decrypted)/2,
        text="m ≡ c^d mod n",
        showarrow=True,
        arrowhead=2
    )
    
    # Update layout with better styling
    fig.update_layout(
        title={
            'text': "RSA Encryption Process Visualization",
            'y':0.95,
            'x':0.5,
            'xanchor': 'center',
            'yanchor': 'top',
            'font': dict(size=24)
        },
        xaxis_title="Process Steps",
        yaxis_title="Values",
        showlegend=True,
        plot_bgcolor='rgba(240,240,240,0.5)',
        paper_bgcolor='white',
        xaxis=dict(
            showgrid=True,
            gridwidth=1,
            gridcolor='rgba(128,128,128,0.2)',
            ticktext=['', 'Prime p', 'Prime q', 'Modulus n', 'φ(n)', 'Public e', 
                     'Message', 'Ciphertext', 'Private d', 'Decrypted'],
            tickvals=list(range(10)),
            tickmode='array'
        ),
        yaxis=dict(
            showgrid=True,
            gridwidth=1,
            gridcolor='rgba(128,128,128,0.2)',
            type='log'  # Using log scale for better visualization of large numbers
        ),
        height=600
    )
    
    return fig

def explain_rsa_steps(p, q, e, m):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    c = pow(m, e, n)
    m_decrypted = pow(c, d, n)
    
    steps = [
        f"1. Choose two prime numbers: p = {p}, q = {q}",
        f"2. Compute n = p * q = {n}",
        f"3. Compute φ(n) = (p-1) * (q-1) = {phi}",
        f"4. Choose e (public exponent): {e}",
        f"5. Compute d (private exponent): {d}",
        f"6. Public key: (e, n) = ({e}, {n})",
        f"7. Private key: (d, n) = ({d}, {n})",
        f"8. Message to encrypt: m = {m}",
        f"9. Encrypt: c ≡ m^e mod n = {c}",
        f"10. Decrypt: m ≡ c^d mod n = {m_decrypted}"
    ]
    return steps

def simulate_small_prime_attack(n):
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return i, n // i
    return None, None

def measure_performance(key_sizes, message_sizes):
    results = []
    for key_size in key_sizes:
        for msg_size in message_sizes:
            start_time = time.time()
            (public_key, private_key), _ = generate_keypair_with_progress(key_size, st.empty())
            key_gen_time = time.time() - start_time
            
            message = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=msg_size))
            
            start_time = time.time()
            encrypted = encrypt(public_key, message)
            encrypt_time = time.time() - start_time
            
            start_time = time.time()
            decrypted = decrypt(private_key, encrypted)
            decrypt_time = time.time() - start_time
            
            results.append({
                'Key Size': key_size,
                'Message Size': msg_size,
                'Key Generation Time': key_gen_time,
                'Encryption Time': encrypt_time,
                'Decryption Time': decrypt_time
            })
    return results

def sign_message(private_key, message):
    d, n = private_key
    # Use SHA-256 instead of built-in hash
    hash_value = int.from_bytes(sha256(message.encode()).digest(), 'big') % n
    signature = pow(hash_value, d, n)
    return signature

def verify_signature(public_key, message, signature):
    e, n = public_key
    hash_value = hash(message) % n  # Simple hash function
    decrypted_signature = pow(signature, e, n)
    return hash_value == decrypted_signature

def interactive_attack_simulation(n, max_attempts=1000):
    results = []
    for attempt in range(max_attempts):
        p_candidate = random.randint(2, int(math.sqrt(n)))
        if n % p_candidate == 0:
            q_candidate = n // p_candidate
            results.append({
                "attempt": attempt + 1,
                "p_found": p_candidate,
                "q_found": q_candidate,
                "success": True
            })
            break
        if attempt % 10 == 0:  # Store some failed attempts too
            results.append({
                "attempt": attempt + 1,
                "p_candidate": p_candidate,
                "success": False
            })
    return results

# Add new function for RSA challenge
def generate_challenge(difficulty):
    """Generate an RSA challenge based on difficulty level"""
    if difficulty == "Easy":
        bits = 16
    elif difficulty == "Medium":
        bits = 32
    else:  # Hard
        bits = 64
        
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    e = 65537
    
    # Generate a random message
    message = random.randint(2, min(n-1, 1000))
    ciphertext = pow(message, e, n)
    
    return {
        'n': n,
        'e': e,
        'ciphertext': ciphertext,
        'message': message  # Store for verification
    }

def verify_challenge_solution(solution, challenge_data):
    """Verify if the submitted solution matches the original message"""
    try:
        solution = int(solution)
        return solution == challenge_data['message']
    except:
        return False

# Add this before the visualization code
security_context = {
    128: {'strength': 'Very Weak', 'color': 'red'},
    256: {'strength': 'Weak', 'color': 'orange'},
    512: {'strength': 'Educational', 'color': 'yellow'},
    1024: {'strength': 'Historical', 'color': 'blue'},
    2048: {'strength': 'Standard', 'color': 'green'},
    4096: {'strength': 'Future-Proof', 'color': 'purple'}
}

# Streamlit UI
st.set_page_config(
    page_title="RSA Cryptosystem Explorer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
    
)

# Update the custom CSS to support both light and dark modes
st.markdown("""
<style>
    /* Modern theme colors and variables */
    :root {
        --primary-color: #2962FF;
        --secondary-color: #0D47A1;
        --text-color: #1A237E;
        --border-radius: 12px;
        --box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }

    /* Dark mode specific variables */
    [data-theme="dark"] {
        --background-color: #1E1E1E;
        --card-background: #2D2D2D;
        --text-color: #E0E0E0;
        --border-color: #404040;
    }

    /* Light mode specific variables */
    [data-theme="light"] {
        --background-color: #F5F7FA;
        --card-background: #FFFFFF;
        --text-color: #1A237E;
        --border-color: #E0E0E0;
    }

    /* Global styles */
    .stApp {
        background-color: var(--background-color);
        color: var(--text-color);
    }

    /* Header styling */
    .main-header {
        background: linear-gradient(120deg, var(--primary-color), var(--secondary-color));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2.8rem;
        font-weight: 800;
        text-align: center;
        padding: 2rem 0;
        margin-bottom: 2rem;
    }

    /* Card container styling */
    .content-card {
        background: var(--card-background);
        border-radius: var(--border-radius);
        padding: 1.5rem;
        margin-bottom: 1.5rem;
        box-shadow: var(--box-shadow);
        border: 1px solid var(--border-color);
    }

    /* Button styling */
    .stButton > button {
        width: 100%;
        background: linear-gradient(45deg, var(--primary-color), var(--secondary-color));
        color: white;
        border: none;
        padding: 0.75rem 1.5rem;
        border-radius: var(--border-radius);
        font-weight: 600;
        transition: all 0.3s ease;
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15);
    }

    /* Input field styling */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea {
        border-radius: var(--border-radius);
        border: 2px solid var(--border-color);
        background-color: var(--card-background);
        color: var(--text-color);
        padding: 0.75rem;
        transition: all 0.3s ease;
    }
    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus {
        border-color: var(--primary-color);
        box-shadow: 0 0 0 2px rgba(41, 98, 255, 0.2);
    }

    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: transparent;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        background-color: var(--card-background);
        border-radius: var(--border-radius);
        padding: 0 24px;
        font-weight: 600;
        color: var(--text-color);
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(45deg, var(--primary-color), var(--secondary-color));
        color: white;
    }

    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background-color: var(--card-background);
        border-right: 1px solid var(--border-color);
    }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h3 {
        color: var(--text-color);
    }

    /* Code block styling */
    .stCodeBlock {
        background-color: var(--card-background) !important;
        border: 1px solid var(--border-color);
    }

    /* Metric styling */
    [data-testid="stMetricValue"] {
        color: var(--primary-color);
    }

    /* Challenge section styling */
    .challenge-container {
        background: var(--card-background);
        padding: 2rem;
        border-radius: var(--border-radius);
        border: 1px solid var(--border-color);
    }
    .challenge-header {
        color: var(--text-color);
    }

    /* Alert/Info box styling */
    .stAlert {
        background-color: var(--card-background);
        color: var(--text-color);
        border-radius: var(--border-radius);
    }

    /* Select box styling */
    .stSelectbox > div > div {
        background-color: var(--card-background);
        color: var(--text-color);
    }

    /* Slider styling */
    .stSlider > div > div {
        color: var(--text-color);
    }

    /* Progress bar styling */
    .stProgress > div > div > div > div {
        background-color: var(--primary-color);
    }
</style>
""", unsafe_allow_html=True)

st.markdown("<h1 class='main-header'>RSA Cryptosystem Explorer</h1>", unsafe_allow_html=True)

# Sidebar for key generation and settings
with st.sidebar:
    with st.container():
        st.markdown("### 🔐 RSA Settings")
        key_size = st.select_slider(
            "Key Size (bits)", 
            options=[128, 256, 512, 1024],
            value=256,
            help="Larger key sizes are more secure but slower"
        )

        # Add visual feedback for key strength
        strength_colors = {
            128: ['Very Weak', '#ff4444'],
            256: ['Weak', '#ffbb33'],
            512: ['Educational', '#00C851'],
            1024: ['Historical', '#33b5e5']
        }
        strength, color = strength_colors.get(key_size, ['Unknown', '#grey'])
        st.markdown(f"""
            <div style='padding: 10px; border-radius: 5px; background-color: {color}25; border-left: 5px solid {color}'>
                <strong>Key Strength:</strong> {strength}
            </div>
        """, unsafe_allow_html=True)

    # Add key generation stats
    if 'key_stats' not in st.session_state:
        st.session_state.key_stats = []

    key_strength, color = get_key_strength(key_size)
    st.markdown(f"Key Strength: <span style='color:{color}'>{key_strength}</span>", unsafe_allow_html=True)
    st.info("Note: For educational purposes only. In practice, use key sizes of 2048 bits or larger.")

    if st.button("Generate Keys", key="generate_keys"):
        with st.spinner("Generating keys..."):
            progress_bar = st.progress(0)
            (public_key, private_key), generation_time = generate_keypair_with_progress(key_size, progress_bar)
            st.session_state.public_key = public_key
            st.session_state.private_key = private_key
            
            # Add stats to the session state
            if 'key_stats' not in st.session_state:
                st.session_state.key_stats = []
            st.session_state.key_stats.append({
                'timestamp': datetime.now(),
                'key_size': key_size,
                'generation_time': generation_time
            })
        
        st.success(f"Keys generated in {generation_time:.2f} seconds!")
        st.write(f"Public Key (e, n): {st.session_state.public_key}")
        st.write(f"Private Key (d, n): {st.session_state.private_key}")

    if st.button("Save Key Pair"):
        if hasattr(st.session_state, 'public_key') and hasattr(st.session_state, 'private_key'):
            key_pair = {
                "public_key": list(st.session_state.public_key),
                "private_key": list(st.session_state.private_key)
            }
            st.download_button(
                "Download Key Pair",
                json.dumps(key_pair),
                "rsa_key_pair.json",
                "application/json"
            )
        else:
            st.error("No keys generated yet.")

    uploaded_key_pair = st.file_uploader("Load Key Pair", type="json")
    if uploaded_key_pair is not None:
        try:
            key_pair = json.loads(uploaded_key_pair.getvalue())
            st.session_state.public_key = tuple(key_pair["public_key"])
            st.session_state.private_key = tuple(key_pair["private_key"])
            st.success("Key pair loaded successfully!")
            st.write(f"Public Key (e, n): {st.session_state.public_key}")
            st.write(f"Private Key (d, n): {st.session_state.private_key}")
        except Exception as e:
            st.error(f"Error loading key pair: {str(e)}")

    st.markdown('</div>', unsafe_allow_html=True)

# Main content area
tabs = st.tabs(["🔒 Encryption/Decryption", "📊 Visualization", "🛠️ Tools", "🎯 Challenges", "ℹ️ About"])

with tabs[0]:
    st.markdown("<div class='content-card'>", unsafe_allow_html=True)
    st.markdown("<h2 class='section-header'>Text & File Operations</h2>", unsafe_allow_html=True)
    
    operation = st.radio(
        "Select Operation",
        ["Text Encryption/Decryption", "File Encryption/Decryption"],
        horizontal=True
    )

    if operation == "Text Encryption/Decryption":
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Encryption")
            plaintext = st.text_area("Enter plaintext to encrypt:", height=150)
            if st.button("Encrypt", key="encrypt_text"):
                if not hasattr(st.session_state, 'public_key') or st.session_state.public_key is None:
                    st.error("Please generate keys first")
                elif not plaintext:
                    st.error("Please enter some text to encrypt")
                else:
                    ciphertext = encrypt(st.session_state.public_key, plaintext)
                    st.session_state.ciphertext = ' '.join(map(str, ciphertext))
                    st.success("Text encrypted successfully!")
                    st.code(st.session_state.ciphertext, language="text")

        with col2:
            st.subheader("Decryption")
            ciphertext_input = st.text_area("Enter ciphertext to decrypt:", height=150, value=st.session_state.get('ciphertext', ''))
            if st.button("Decrypt", key="decrypt_text"):
                if not hasattr(st.session_state, 'private_key') or st.session_state.private_key is None:
                    st.error("Please generate keys first")
                else:
                    try:
                        ciphertext = list(map(int, ciphertext_input.split()))
                        plaintext = decrypt(st.session_state.private_key, ciphertext)
                        st.success("Text decrypted successfully!")
                        st.code(plaintext, language="text")
                    except ValueError:
                        st.error("Invalid ciphertext format. Please enter space-separated integers.")
                    except Exception as e:
                        st.error(f"An error occurred during decryption: {str(e)}")

    else:
        uploaded_file = st.file_uploader("Choose a file")

        if uploaded_file is not None:
            file_contents = uploaded_file.read()
            col3, col4 = st.columns(2)
            
            with col3:
                if st.button("Encrypt File", key="encrypt_file"):
                    if not hasattr(st.session_state, 'public_key') or st.session_state.public_key is None:
                        st.error("Please generate keys first")
                    else:
                        progress_bar = st.progress(0)
                        encrypted_data = encrypt_file_with_progress(st.session_state.public_key, file_contents, progress_bar)
                        st.session_state.encrypted_file = ' '.join(map(str, encrypted_data))
                        st.success("File encrypted successfully!")
                        st.download_button(
                            "Download Encrypted File",
                            st.session_state.encrypted_file,
                            "encrypted_file.txt",
                            mime="text/plain"
                        )
            
            with col4:
                if st.button("Decrypt File", key="decrypt_file"):
                    if not hasattr(st.session_state, 'private_key') or st.session_state.private_key is None:
                        st.error("Please generate keys first")
                    else:
                        try:
                            progress_bar = st.progress(0)
                            encrypted_data = list(map(int, file_contents.decode().split()))
                            decrypted_data = decrypt_file_with_progress(st.session_state.private_key, encrypted_data, progress_bar)
                            st.success("File decrypted successfully!")
                            st.download_button(
                                "Download Decrypted File",
                                decrypted_data,
                                "decrypted_file",
                                mime="application/octet-stream"
                            )
                        except Exception as e:
                            st.error(f"Error during decryption: {str(e)}")

    st.markdown('</div>', unsafe_allow_html=True)

with tabs[1]:
    st.markdown("<h2 class='section-header'>RSA Process Visualization</h2>", unsafe_allow_html=True)
    viz_type = st.selectbox(
        "Select Visualization",
        ["Process Flow", "Performance Comparison", "Key Generation Stats"]
    )
    
    if viz_type == "Process Flow":
        st.markdown('<div class="content-card">', unsafe_allow_html=True)
        if hasattr(st.session_state, 'public_key') and hasattr(st.session_state, 'private_key'):
            e, n = st.session_state.public_key
            d, _ = st.session_state.private_key
            p, q = 17, 19  # Example small primes for visualization
            m = 42  # Example message
            fig = visualize_rsa_process(p, q, e, d, m)
            st.plotly_chart(fig)
        else:
            st.error("Please generate keys first")
        st.markdown('</div>', unsafe_allow_html=True)
    elif viz_type == "Performance Comparison":
        st.markdown('<div class="content-card">', unsafe_allow_html=True)
        key_sizes = [128, 256, 512, 1024]
        message_sizes = [100, 1000, 10000]
        
        with st.spinner("Measuring RSA performance across different key sizes..."):
            results = []
            progress_bar = st.progress(0)
            total_iterations = len(key_sizes) * len(message_sizes)
            current_iteration = 0
            
            for key_size in key_sizes:
                for msg_size in message_sizes:
                    current_iteration += 1
                    progress_bar.progress(current_iteration / total_iterations)
                    
                    # Perform measurements
                    start_time = time.time()
                    (public_key, private_key), _ = generate_keypair_with_progress(key_size, st.empty())
                    key_gen_time = time.time() - start_time
                    
                    message = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=msg_size))
                    
                    start_time = time.time()
                    encrypted = encrypt(public_key, message)
                    encrypt_time = time.time() - start_time
                    
                    start_time = time.time()
                    decrypted = decrypt(private_key, encrypted)
                    decrypt_time = time.time() - start_time
                    
                    total_time = key_gen_time + encrypt_time + decrypt_time
                    
                    results.append({
                        'Key Size': int(key_size),
                        'Message Size': int(msg_size),
                        'Key Generation': float(key_gen_time),
                        'Encryption': float(encrypt_time),
                        'Decryption': float(decrypt_time),
                        'Total Time': float(total_time)
                    })
            
            df = pd.DataFrame(results)
            
            # Create visualization
            fig = go.Figure()
            
            operations = ['Key Generation', 'Encryption', 'Decryption']
            colors = ['#1f77b4', '#ff7f0e', '#2ca02c']
            
            for op, color in zip(operations, colors):
                for key_size in sorted(df['Key Size'].unique()):
                    df_subset = df[df['Key Size'] == key_size]
                    fig.add_trace(go.Scatter(
                        x=df_subset['Message Size'],
                        y=df_subset[op],
                        mode='lines+markers',
                        name=f'{key_size}-bit ({op})',
                        line=dict(color=color, dash='solid' if op == 'Key Generation' else 'dot'),
                        marker=dict(size=8, symbol='circle'),
                    ))

            fig.update_layout(
                title='RSA Performance Analysis',
                xaxis_title='Message Size (characters)',
                yaxis_title='Time (seconds)',
                yaxis_type='log',
                showlegend=True
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Display summary statistics
            st.subheader("Performance Summary")
            summary_df = df.groupby('Key Size').agg({
                'Key Generation': 'mean',
                'Encryption': 'mean',
                'Decryption': 'mean',
                'Total Time': 'mean'
            }).round(3)
            
            st.dataframe(summary_df)
            
            # Display security context
            st.subheader("Security Context")
            for key_size in sorted(security_context.keys()):
                if key_size in df['Key Size'].unique():
                    st.write(f"**{key_size}-bit**: {security_context[key_size]['strength']}")
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        # New visualization for key generation stats
        if len(st.session_state.key_stats) > 0:
            df = pd.DataFrame(st.session_state.key_stats)
            
            # Create the chart with proper configuration
            chart = alt.Chart(df).mark_line(point=True).encode(
                x=alt.X('timestamp:T', title='Time'),
                y=alt.Y('generation_time:Q', title='Generation Time (seconds)'),
                color=alt.Color('key_size:N', title='Key Size (bits)')
            ).properties(
                width=600,
                height=400,
                title='Key Generation Performance Over Time'
            ).interactive()
            
            st.altair_chart(chart, use_container_width=True)
            
            # Also display the raw data
            st.subheader("Raw Data")
            st.dataframe(df[['timestamp', 'key_size', 'generation_time']].sort_values('timestamp', ascending=False))
        else:
            st.info("No key generation data available yet. Generate some keys to see the statistics!")

    st.markdown('</div>', unsafe_allow_html=True)

with tabs[2]:
    st.markdown("<div class='content-card'>", unsafe_allow_html=True)
    st.markdown("<h2 class='section-header'>RSA Tools</h2>", unsafe_allow_html=True)
    tool = st.selectbox(
        "Select Tool",
        ["Step Calculator", "Attack Simulator", "Digital Signature"]
    )
    
    if tool == "Step Calculator":
        col1, col2 = st.columns(2)
        with col1:
            calc_p = st.number_input("Enter p (small prime)", min_value=2, value=17)
            calc_q = st.number_input("Enter q (small prime)", min_value=2, value=19)
            calc_m = st.number_input("Enter message (m)", min_value=0, value=42)
        
        if st.button("Calculate Steps"):
            calc_n = calc_p * calc_q
            calc_phi = (calc_p - 1) * (calc_q - 1)
            calc_e = 65537
            try:
                calc_d = pow(calc_e, -1, calc_phi)
                calc_c = pow(calc_m, calc_e, calc_n)
                calc_m_decrypted = pow(calc_c, calc_d, calc_n)
                
                st.write("**Step-by-step calculation:**")
                st.write(f"1. n = p × q = {calc_p} × {calc_q} = {calc_n}")
                st.write(f"2. φ(n) = (p-1) × (q-1) = {calc_p-1} × {calc_q-1} = {calc_phi}")
                st.write(f"3. e = {calc_e}")
                st.write(f"4. d = e⁻¹ mod φ(n) = {calc_d}")
                st.write(f"5. c = m^e mod n = {calc_m}^{calc_e} mod {calc_n} = {calc_c}")
                st.write(f"6. m = c^d mod n = {calc_c}^{calc_d} mod {calc_n} = {calc_m_decrypted}")
            except Exception as e:
                st.error(f"Calculation error: {str(e)}")

    elif tool == "Attack Simulator":
        small_n = st.number_input("Enter a small number to factor (simulating weak RSA)", min_value=4, max_value=10000, value=77)
        if st.button("Simulate Small Prime Attack"):
            start_time = time.time()
            p, q = simulate_small_prime_attack(small_n)
            end_time = time.time()
            if p and q:
                st.write(f"Factored {small_n} into p = {p} and q = {q}")
                st.write(f"Time taken: {end_time - start_time:.6f} seconds")
            else:
                st.write(f"Failed to factor {small_n} (it might be prime)")

    else:
        message_to_sign = st.text_input("Enter a message to sign:")
        col3, col4 = st.columns(2)
        with col3:
            if st.button("Sign Message"):
                if hasattr(st.session_state, 'private_key'):
                    signature = sign_message(st.session_state.private_key, message_to_sign)
                    st.session_state.signature = signature
                    st.write(f"Signature: {signature}")
                else:
                    st.error("Please generate keys first")

        with col4:
            if st.button("Verify Signature"):
                if hasattr(st.session_state, 'public_key') and hasattr(st.session_state, 'signature'):
                    is_valid = verify_signature(st.session_state.public_key, message_to_sign, st.session_state.signature)
                    if is_valid:
                        st.success("Signature is valid!")
                    else:
                        st.error("Signature is invalid!")
                else:
                    st.error("Please generate keys and sign a message first")
    # Add to Tools tab

    st.markdown('</div>', unsafe_allow_html=True)

with tabs[3]:
    st.markdown("### 🎯 RSA Challenges")
    
    # Add a stats container
    stats_container = st.container()
    with stats_container:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Difficulty", st.session_state.get('current_difficulty', 'Not Started'))
        with col2:
            st.metric("Challenges Solved", st.session_state.get('challenges_solved', 0))
        with col3:
            st.metric("Current Attempts", st.session_state.get('challenge_attempts', 0))

    # Challenge controls
    with st.form("challenge_form"):
        difficulty = st.select_slider(
            "Select Difficulty",
            options=["Easy", "Medium", "Hard"],
            value="Easy"
        )
        submit_challenge = st.form_submit_button("Generate New Challenge")
        
        if submit_challenge:
            st.session_state.current_difficulty = difficulty
            st.session_state.current_challenge = generate_challenge(difficulty)
            st.session_state.challenge_attempts = 0
            st.rerun()  # Updated from experimental_rerun()

    # Challenge details and solution input
    if st.session_state.get('current_challenge'):
        st.markdown("""
        <div style='background: #f8f9fa; padding: 1rem; border-radius: 8px; margin: 1rem 0;'>
            <h4 style='margin-top: 0;'>Current Challenge</h4>
        </div>
        """, unsafe_allow_html=True)
        
        # Display challenge parameters in a code block
        st.code(f"""
n (modulus) = {st.session_state.current_challenge['n']}
e (public exponent) = {st.session_state.current_challenge['e']}
ciphertext = {st.session_state.current_challenge['ciphertext']}
        """, language="python")
        
        # Solution input and verification
        col3, col4 = st.columns([3, 1])
        with col3:
            solution = st.text_input("Enter your solution (the original message):")
        with col4:
            if st.button("Submit"):
                if verify_challenge_solution(solution, st.session_state.current_challenge):
                    st.success("🎉 Correct! You've solved the challenge!")
                    st.session_state.challenges_solved = st.session_state.get('challenges_solved', 0) + 1
                else:
                    st.error("❌ Incorrect solution. Try again!")
                    st.session_state.challenge_attempts = st.session_state.get('challenge_attempts', 0) + 1
        
        # Show/Hide Solution Button
        if st.button("Show/Hide Solution"):
            st.session_state.show_solution = not st.session_state.get('show_solution', False)
        
        # Display Solution when toggled
        if st.session_state.get('show_solution', False):
            with st.expander("Solution", expanded=True):
                n = st.session_state.current_challenge['n']
                e = st.session_state.current_challenge['e']
                c = st.session_state.current_challenge['ciphertext']
                m = st.session_state.current_challenge['message']
                
                st.markdown("""
                ### Step-by-Step Solution:
                """)
                
                # Find factors
                p, q = simulate_small_prime_attack(n)
                phi_n = (p-1) * (q-1)
                d = pow(e, -1, phi_n)
                
                st.code(f"""
# Given values:
n = {n}  # modulus
e = {e}  # public exponent
c = {c}  # ciphertext

# Step 1: Factor n into p and q
p = {p}
q = {q}
# Verify: {p} × {q} = {n}

# Step 2: Calculate φ(n) = (p-1)(q-1)
φ(n) = ({p}-1) × ({q}-1) = {phi_n}

# Step 3: Calculate private exponent d
d = e⁻¹ mod φ(n) = {d}

# Step 4: Decrypt message
m = c^d mod n = {m}

Therefore, the original message is: {m}
                """)
    else:
        st.info("Click 'Generate New Challenge' to start!")
    
    st.markdown("</div></div>", unsafe_allow_html=True)
    
    # Hints and How to Play sections as expandable cards
    col5, col6 = st.columns(2)
    with col5:
        with st.expander("📝 Hints"):
            st.markdown("""
            1. For easy challenges, try factoring n into p and q
            2. Once you have p and q, calculate φ(n) = (p-1)(q-1)
            3. Find d = e⁻¹ mod φ(n)
            4. Decrypt using m = c^d mod n
            """)
    
    with col6:
        with st.expander("📚 How to Play"):
            st.markdown("""
            1. Choose your difficulty level
            2. Generate a new challenge
            3. Try to decrypt the message using RSA principles
            4. Submit your solution
            5. Use hints if needed
            """)

    st.markdown('</div>', unsafe_allow_html=True)

with tabs[4]:
    st.markdown("<div class='content-card'>", unsafe_allow_html=True)
    st.markdown("<h2 class='section-header'>About This RSA Implementation</h2>", unsafe_allow_html=True)
    with st.expander("Click to expand"):
        st.markdown("""
        <div class='info-box'>
        This is a simplified RSA implementation for educational purposes. It demonstrates the key concepts of RSA encryption:

        1. **Key Generation**:
           - Generate two large prime numbers, p and q
           - Compute n = p * q (the modulus)
           - Compute φ(n) = (p-1) * (q-1) (Euler's totient function)
           - Choose e (public exponent) such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
           - Compute d (private exponent) such that d ≡ e^(-1) mod φ(n)

        2. **Encryption**:
           - Convert the message to a number m
           - Compute ciphertext c ≡ m^e mod n

        3. **Decryption**:
           - Compute plaintext m  c^d mod n

        This implementation uses smaller key sizes to speed up the process. Note: These key sizes are NOT secure for real-world use. This implementation is for learning and demonstration only.
        </div>
        """, unsafe_allow_html=True)

    st.warning("Warning: Do not use this implementation for any real-world security purposes. It is designed for educational use only.")

    # Add this to your About tab
    with tabs[4]:
        st.markdown("""
        ### 📚 Documentation
        
        #### How to Use This App
        1. **Generate Keys**: Use the sidebar to select key size and generate RSA keys
        2. **Encrypt/Decrypt**: Use the first tab to encrypt or decrypt messages
        3. **Visualize**: See the RSA process visualization in the second tab
        4. **Tools**: Explore RSA tools in the third tab
        5. **Challenges**: Test your understanding with RSA challenges
        
        #### Security Notice
        This is an educational tool. For real-world applications:
        - Use key sizes of 2048 bits or larger
        - Use established cryptographic libraries
        - Never share private keys
        
        #### Updates & Feedback
        - Visit [GitHub Repository](https://github.com/DD-og/RSA-Cryptosystem-Explorer.git)
        - Report issues or suggest features
        - Star the repository if you find it helpful
        """)

    st.markdown('</div>', unsafe_allow_html=True)

# Replace the existing footer with this updated version
st.markdown("""
    <footer style='
        position: fixed;
        bottom: 0;
        left: 0;
        width: 100%;
        background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
        color: white;
        padding: 1rem;
        text-align: center;
        box-shadow: 0 -2px 10px rgba(0, 0, 0, 0.1);
        z-index: 1000;
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 2rem;
    '>
        <div style='display: flex; align-items: center; gap: 0.5rem;'>
            <span>Made with</span>
            <span style='color: #ff4b4b; font-size: 1.2rem;'>❤️</span>
            <span>by DD-og</span>
        </div>
        <div style='display: flex; gap: 1rem;'>
            <a href='https://github.com/DD-og' style='
                color: white;
                text-decoration: none;
                padding: 0.5rem 1rem;
                border-radius: 20px;
                background: rgba(255, 255, 255, 0.1);
                transition: all 0.3s ease;
            '>
                <i class="fab fa-github"></i> GitHub
            </a>
        </div>
    </footer>
    
    <!-- Add padding to prevent content from being hidden behind fixed footer -->
    <div style='padding-bottom: 4rem;'></div>
""", unsafe_allow_html=True)
