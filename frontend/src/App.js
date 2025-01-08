// to run this file: npm start

import React from 'react';
import { Route, Routes } from 'react-router-dom'; // to define routes and render specific components based on the current URL
//import { response } from 'express'; // don't use this! the 'express' package is a server-side package, and shouldn't be included on the client-side
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import Profile from './pages/Profile';
import Login from './pages/Login';
import SignUp from './pages/SignUp';
import PrivateRoute from './PrivateRoute';
import AddProject from './pages/AddProject';


function App() {
  return (
    <>
      {/* <Navbar /> */}
      <Routes>
        {/* Public Routes */}
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<SignUp />} />

        {/* Protected Routes */}
        <Route
          path="/dashboard"
          element={
            <PrivateRoute>
              <Navbar />
              <Dashboard />
            </PrivateRoute>
          }
        />

        <Route
          path="/profile"
          element={
            <PrivateRoute>
              <Navbar />
              <Profile />
            </PrivateRoute>
          }
        />

        <Route
          path="/add-project"
          element={
            <PrivateRoute>
              <Navbar />
              <AddProject />
            </PrivateRoute>
          }
        />

        {/* Default Route */}
        <Route path="*" element={<Login />} />
      </Routes>
    </>
  );
}

export default App;
