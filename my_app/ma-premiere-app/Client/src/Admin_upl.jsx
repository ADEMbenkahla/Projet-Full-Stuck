import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const UploadFileComponent = () => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadStatus, setUploadStatus] = useState('');
  const navigate = useNavigate();

  const handleFileChange = (event) => {
    setSelectedFile(event.target.files[0]);
  };

  const handleUpload = () => {
    if (selectedFile) {
      const formData = new FormData();
      formData.append('image', selectedFile); // Utilisez "image" comme nom de la propriété

      axios.post('http://localhost:3100/api/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        onUploadProgress: (progressEvent) => {
          const progress = Math.round((progressEvent.loaded / progressEvent.total) * 100);
          setUploadProgress(progress);
        }
      })
        .then(res => {
          setUploadStatus('Image téléversée avec succès.');
          navigate('/etudiant'); // Rediriger vers la page "etudiant" après le téléversement
        })
        .catch(error => {
          console.error('Erreur lors du téléversement de l\'image:', error);
          setUploadStatus('Erreur lors du téléversement de l\'image.');
        });
    }
  };

  const handleBack = () => {
    navigate('/Admin_aff');
  };

  return (
    <div>
      <h2>Téléverser une image</h2>
      <input type="file" onChange={handleFileChange} />
      <button onClick={handleUpload}>Téléverser</button>
      {uploadProgress > 0 && <p>Progression: {uploadProgress}%</p>}
      {uploadStatus && <p>{uploadStatus}</p>}
      <button onClick={handleBack}>Retour</button>
    </div>
  );
};

export default UploadFileComponent;
