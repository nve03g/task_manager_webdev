import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from './AuthContext';

const PrivateRoute = ({ children }) => {
  const { authToken } = useAuth();

  // redirect to login if no valid token exists
  return authToken ? children : <Navigate to="/login" />; // was return authToken ? children : <Navigate to="/login" replace />;
};

export default PrivateRoute;
