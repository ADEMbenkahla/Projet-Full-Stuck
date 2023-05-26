import React, { useState } from "react";
import logo from './logo.svg';
import './App.css';
import { Login } from "./Login";
import { Register } from "./Register";
import { Route, Routes } from 'react-router-dom';
import Interface from './Interface';
import Admin_upl from './Admin_upl';
import Admin_aff from './Admin_aff';
import Etudiant from './Etudiant';
import TI11 from './TI11';
import TI12 from './TI12';
import DSI2 from './DSI2';
import DSI3 from './DSI3';

function App() {

  return (
    <div className="App">

      <Routes>
        <Route path='/' element={<Interface />} >
          <Route index element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path='/Admin_upl' element={<Admin_upl />} />
          <Route path='/admin_aff' element={<Admin_aff />} />
          <Route path='/Etudiant' element={<Etudiant />} />
          <Route path='/TI11' element={<TI11/>} />
          <Route path='/TI12' element={<TI12/>} />
          <Route path='/DSI2' element={<DSI2/>} />
          <Route path='/DSI3' element={<DSI3/>} />
        </Route>
      </Routes>

    </div>
  );
}

export default App;
