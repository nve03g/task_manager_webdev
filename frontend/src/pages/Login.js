import React, { useState } from 'react';
import { useAuth } from '../AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import '../styles/login.css';

const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const { login } = useAuth(); // access authToken and login function from AuthContext
    const navigate = useNavigate();

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
                setError(data.error || 'Invalid username or password.');
                return; // exit early if login fails
            }

            login(data.token); // log in user
            setError(null);

            // replace the login page in the browser's history
            // navigate('/dashboard', { replace: true }); // redirect to dashboard
        } catch (err) {
            console.error('Login error:', error);
            setError('An error occured. Please try again.');
        }
    };

    return (
        <div className="login-container">
            <div className="login-box">
                <h1>Login</h1>
                {error && <p className="error-message">{error}</p>}
                <form onSubmit={handleSubmit}>
                    <input
                        type="text"
                        placeholder="Username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        required
                        className="login-input"
                    />
                    <input
                        type="password"
                        placeholder="Password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                        className="login-input"
                    />
                    <button type="submit" className="login-button">Login</button>
                </form>
                <p className="signup-link">
                    Don't have an account? <Link to="/signup">Sign up here</Link>
                </p>
            </div>
        </div>
    );
};

export default Login;