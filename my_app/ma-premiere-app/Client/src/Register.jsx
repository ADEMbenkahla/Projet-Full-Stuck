import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";

export const Register = (props) => {
    const navigate = useNavigate();
    const [nom, setNom] = useState('');
    const [prenom, setPrenom] = useState('');
    const [ddn, setDdn] = useState('');
    const [carteEtudiant, setCarteEtudiant] = useState('');
    const [classe, setClasse] = useState('');
    const [email, setEmail] = useState('');
    const [pass, setPass] = useState('');
    const handleSubmit = (e) => {

        let errorStatus = ''
        const url = "http://localhost:3100/api/registre"

        e.preventDefault();
        console.log(email);
        const data = {
            //1er back
            nom: nom,
            prenom: prenom,
            ddn: ddn,
            carteEtudiant: carteEtudiant,
            classe: classe,
            email: email,
            password: pass
        }
        axios.post(url, data).then(res => {
            console.log("res data", res.data)
            navigate("/")
        }).catch(error => {
            if (!error.response) {
                // network error
                errorStatus = 'Error: Network Error';
            } else {
                errorStatus = error.response.data.message;

            }
        })
    }
    return (
        <div className="auth-form-container">
        <h2>Register</h2>
    <form className="register-form" onSubmit={handleSubmit}>
        <label htmlFor="name">last name</label>
        <input value={nom} name="name" onChange={(e) => setNom(e.target.value)} id="lastName" placeholder="Last Name" />
        <label htmlFor="prenom">First name</label>
        <input value={prenom} name="prenom" onChange={(e) => setPrenom(e.target.value)} id="FirstName" placeholder="First Name" />
        <label htmlFor="ddn">Date of birth</label>
        <input value={ddn} name="ddn" onChange={(e) => setDdn(e.target.value)} id="ddn" placeholder="ddn" />
        <label htmlFor="carteEtudiant">Student cart</label>
        <input value={carteEtudiant} name="carteEtudiant" onChange={(e) => setCarteEtudiant(e.target.value)} id="carteEtudiant" placeholder="CarteEtudiant" />
        
        <label htmlFor="classe">Class</label>
        <select onChange={(e) => setClasse(e.target.value)} >
        <option >----------------</option>
                    <option value="TI11">TI11</option>
                    <option value="TI12">TI12</option>
                    <option value="DSI2">DSI2</option>   
                    <option value="DSI3">DSI3</option>               
        </select>
        <label htmlFor="email">email</label>
        <input value={email} onChange={(e) => setEmail(e.target.value)}type="email" placeholder="youremail@gmail.com" id="email" name="email" />
        <label htmlFor="password">password</label>
        <input value={pass} onChange={(e) => setPass(e.target.value)} type="password" placeholder="********" id="password" name="password" />
        <button type="submit">Log In</button>
            </form>
            <Link className="link-btn" to={"/"}>Already have an account? Login here.</Link>
        </div>
    )
}