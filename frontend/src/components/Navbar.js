import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import '../styles/Navbar.css';

const Navbar = () => {
    const { logout } = useAuth(); // Ensure `useAuth` is not returning undefined
    
    return (
        <nav className="navbar">
            <div className="navbar-logo">
                <a href="/">Task Manager</a>
            </div>
            <ul className="navbar-links">
                <li><a href="/dashboard">Dashboard</a></li>
                <li><a href="/profile">Profile</a></li>
                <li><button className="logout-button" onClick={logout}>Logout</button></li>
            </ul>
        </nav>
    );
};

export default Navbar;