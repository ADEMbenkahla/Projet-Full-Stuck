import React, { useState, useEffect } from "react";
import axios from "axios";
import { Link } from "react-router-dom";
import { useNavigate } from 'react-router-dom';

function ReadNV() {
  const [users, setUsers] = useState([]);
  const [expandedUserId, setExpandedUserId] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    axios
      .get("http://localhost:3100/api/getAllUser")
      .then(res => {
        setUsers(res.data);
      })
      .catch(err => {
        console.log(err);
      });
  }, []);

  const handleReadMore = (userId) => {
    setExpandedUserId(userId);
  };

  const handleHideDetails = () => {
    setExpandedUserId(null);
  };

  const handleDeleteUser = (userId) => {
    axios
      .get(`http://localhost:3100/api/removeUser/${userId}`)
      .then(res => {
        console.log(res.data.message);
        // Actualiser la liste des utilisateurs après la suppression réussie
        axios
          .get("http://localhost:3100/api/getAllUser")
          .then(res => {
            setUsers(res.data);
          })
          .catch(err => {
            console.log(err);
          });
      })
      .catch(err => {
        console.log(err);
      });
  };

  const handleBack = () => {
    navigate('/');
  };
  return (
    <div>
      <h1>Liste des utilisateurs</h1>
      <div>
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Nom</th>
              <th>Prénom</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user, index) => (
              <tr key={user.id}>
                <td>{index + 1}</td>
                <td>{user.nom}</td>
                <td>{user.prenom}</td>
                <td>
                  {expandedUserId === user.id ? (
                    <div>
                      <p>carteEtudiant: {user.carteEtudiant}</p>
                      <p>DDN: {user.ddn}</p>
                      <p>Classe: {user.classe}</p>
                      <p>Email: {user.email}</p>
                      <button
                        className="btn btn-sm btn-primary"
                        onClick={handleHideDetails}
                      >
                        Hide details
                      </button>
                      <button
                        className="btn btn-sm btn-danger"
                        onClick={() => handleDeleteUser(user.id)}
                      >
                        Delete
                      </button>
                    </div>
                  ) : (
                    <button
                      className="btn btn-sm btn-warning"
                      onClick={() => handleReadMore(user.id)}
                    >
                      Read more
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <br />
      <Link to="/Admin_upl">
        <button>Upload</button>
      </Link>
      <button onClick={handleBack}>Retour</button>
    </div>
  );
}

export default ReadNV;
