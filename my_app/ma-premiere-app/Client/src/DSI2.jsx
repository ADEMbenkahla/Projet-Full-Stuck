import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const EtudiantPage = () => {
  const [fileData, setFileData] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    fetchFileData();
  }, []);

  const fetchFileData = () => {
    const token = localStorage.getItem('token'); // Retrieve the authentication token from localStorage

    axios
      .get('http://localhost:3100/api/getFileData', {
        headers: {
          Authorization: token // Send the token in the request headers
        }
      })
      .then(res => {
        setFileData(res.data);
        console.log(res.data);
      })
      .catch(error => {
        console.error('Error fetching file data:', error);
      });
  };

  const handleBack = () => {
    navigate('/');
  };

  return (
    <div>
      <h2>Page Etudiant</h2>
      {fileData.length > 0 ? (
        <div>
          <h3>Images téléversées :</h3>
          {fileData.map(file => (
            <div key={file.id}>
              <p>Nom du fichier: {file.filename}</p>
              <img src={`http://localhost:3100/${file.path}`} alt="Image téléversée" />
              <hr />
            </div>
          ))}
        </div>
      ) : (
        <p>Aucune image disponible.</p>
      )}
      <button onClick={handleBack}>Retour</button>
    </div>
  );
};

export default EtudiantPage;