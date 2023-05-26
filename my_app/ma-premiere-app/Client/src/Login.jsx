import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";

export const Login = (props) => {
    const navigate = useNavigate();
    const [email, setEmail] = useState('');
    const [pass, setPass] = useState('');
    const [error, setError] = useState('');

    const handleSubmit = (e) => {
        e.preventDefault();
      
        if (email.length === 0 || pass.length === 0) {
          setError('Email and password cannot be empty.');
          return;
        }
      
        const url = "http://localhost:3100/api/login";
        const data = {
          email: email,
          password: pass
        };
      
        axios.post(url, data)
          .then(res => {
            // Store the authentication token in localStorage
            localStorage.setItem("token", res.data.token);
            console.log( res.data);
            // navigate("/Etudiant");
            switch (res.data.user.classe) {
                case "TI11":
                    return navigate("/TI11");
                case "TI12":
                    return navigate("/TI12");
                case "DSI2":
                    return navigate("/DSI2")
                case "DSI3":
                    return navigate("/DSI3")
                default:
                    return null
            };
          })
          .catch(error => {
            if (!error.response) {
              setError('Error: Network Error');
            } else {
              setError(error.response.data.message);
            }
          });
      };
      

    return (
        <div className="auth-form-container">
            <h2>Login</h2>
            <form className="login-form" onSubmit={handleSubmit}>
                <label htmlFor="email">Email</label>
                <input
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    type="text"
                    placeholder="youremail@gmail.com"
                    id="email"
                    name="email"
                />
                <label htmlFor="password">Password</label>
                <input
                    value={pass}
                    onChange={(e) => setPass(e.target.value)}
                    type="password"
                    placeholder="************************************"
                    id="password"
                    name="password"
                />
                {error && <label className="err">{error}</label>}
                <button type="submit">Log In</button>
            </form>
            <Link className="link-btn" to={"/register"}>
                Don't have an account? Register here.
            </Link>
        </div>
    );
};