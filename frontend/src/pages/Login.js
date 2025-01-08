import React, { useState, useEffect } from 'react';
import { useAuth } from '../AuthContext';
import { useNavigate } from 'react-router-dom';
// import './Login.css';

const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const { authToken, login } = useAuth(); // access authToken and login function from AuthContext
    const navigate = useNavigate();

    // useEffect(() => {
    //     // redirect to dashboard if already logged in
    //     if (authToken) {
    //         navigate('/dashboard', { replace: true });
    //     }
    // }, [authToken, navigate]);

    const handleSubmit = async (e) => {
        e.preventDefault();

        try {
            const response = await fetch('https://localhost:443/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password }),
            });

            const data = await response.json();
            console.log('Login API response:', data);

            if (!response.ok) {
                throw new Error(data.error || 'Failed to login.');
            }

            login(data.token); // log in user

            // replace the login page in the browser's history
            // navigate('/dashboard', { replace: true }); // redirect to dashboard
        } catch (err) {
            console.error('Login error:', error);
            setError('Invalid username or password.');
        }
    };

    return (
        <div>
            <h1>Login</h1>
            {error && <p style={{ color: 'red' }}>{error}</p>}
            <form onSubmit={handleSubmit}>
                <input
                    type="text"
                    placeholder="Username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                />
                <input
                    type="password"
                    placeholder="Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                />
                <button type="submit">Login</button>
            </form>
            <p>
                Don't have an account? <Link to="/signup">Sign up here</Link>
            </p>
        </div>
    );
};

export default Login;