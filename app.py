from flask import Flask, render_template, request, redirect, url_for
import os
import pickle
from extract_features import extract_characteristics

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Load the trained model
with open('model.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

def detect_ransomware(features):
    result = model.predict([features])
    return result

@app.route('/')
def index():
    return render_template('umum.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    
    file = request.files['file']
    
    if file.filename == '':
        return redirect(request.url)
    
    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        
        # Ekstraksi karakteristik
        characteristics = extract_characteristics(file_path)
        
        # Siapkan data untuk prediksi
        feature_vector = [
            characteristics['machine'],
            characteristics['DebugSize'],
            characteristics['DebugRVA'],
            characteristics['major_image_version'],
            characteristics['major_os_version'],
            characteristics['ExportRVA'],
            characteristics['ExportSize'],
            characteristics['IatVRA'],
            characteristics['major_linker_version'],
            characteristics['minor_linker_version'],
            characteristics['number_of_sections'],
            characteristics['size_of_stack_reserve'],
            characteristics['dll_characteristics'],
            characteristics['ResourceSize'],
            characteristics['BitcoinAddresses']
        ]
        
        is_ransomware = detect_ransomware(feature_vector)
        characteristics['is_ransomware'] = 'Aman' if is_ransomware[0] == 1 else 'Ransomware'
        
        return render_template('umum.html', result=characteristics)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))