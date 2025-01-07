import React, { createContext, useState, useEffect, useContext } from 'react';
import { useNavigate } from 'react-router-dom';

// create AuthContext
const AuthContext = createContext();

// custom hook to access the AuthContext
export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};

// AuthProvider component
export const AuthProvider = ({ children }) => {
    const [authToken, setAuthToken] = useState(localStorage.getItem('authToken'));
    const [isLoading, setIsLoading] = useState(true); // add loading state
    const navigate = useNavigate();

    // check token validity on load
    useEffect(() => {
        const validateToken = async () => {
            if (authToken) {
                try {
                    const response = await fetch('https://localhost:443/validate-token', {
                        method: 'POST',
                        headers: { Authorization: `Bearer ${authToken}` },
                    });

                    if (!response.ok) {
                        throw new Error('Invalid token');
                    }

                    // token is valid, allow the app to proceed
                    setIsLoading(false);
                } catch (error) {
                    console.error('Token validation failed:', error);
                    logout(); // log out if token is invalid
                }
            }
            else {
                setIsLoading(false); // no token, directly mark loading state as 'not loading'
                // navigate('/login', { replace: true });
            }
        };

        validateToken();
    }, [authToken]);

    const login = (token) => {
        localStorage.setItem('authToken', token);
        setAuthToken(token);
        navigate('/dashboard'); // redirect to dashboard after login
    };

    const logout = () => {
        localStorage.removeItem('authToken');
        setAuthToken(null);
        navigate('/login'); // , { replace: true } // redirect to login page after logout, replace current page
    };

    if (isLoading) {
        // add a loading spinner or placeholder while token is being validated
        return <div>Loading...</div>;
    }

    return (
        <AuthContext.Provider value={{ authToken, login, logout }}>
            {children}
        </AuthContext.Provider>
    );
};
