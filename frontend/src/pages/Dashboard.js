import React, { useState, useEffect } from 'react';
import Navbar from '../components/Navbar';
import { useAuth } from '../AuthContext';
import { useNavigate } from 'react-router-dom';
// import './Dashboard.css';

const Dashboard = () => {
    const [projects, setProjects] = useState([]);
    const [error, setError] = useState(null);
    const { authToken } = useAuth(); // access the authentication token from the AuthContext
    const navigate = useNavigate();

    // useEffect(() => {
    //     if (!authToken) {
    //         navigate('/login', { replace: true });
    //     }
    //     // // clear history by replacing the current state
    //     // window.history.replaceState(null, '', window.location.href);

    //     // // // redirect to login if no valid token is present
    //     // // const token = localStorage.getItem('authToken');
    //     // // if (!token) {
    //     // //     navigate('/login', { replace: true });
    //     // // }
    // }, []);

    useEffect(() => {
        const fetchProjects = async () => {
            try {
                const response = await fetch('https://localhost:443/projects', {
                    headers: {
                        Authorization: `Bearer ${authToken}`, // send token in Authorization header
                    },
                });

                const data = await response.json();
                console.log('API response:', data);

                if (!response.ok) {
                    throw new Error(data.error || 'Failed to fetch projects');
                }

                setProjects(Array.isArray(data.projects) ? data.projects : []); // this ensures that projects is always an array
            } catch (error) {
                console.error('Error fetching projects:', error);
                setError('Failed to load projects. Please try again.');
            }
        };

        fetchProjects();
    }, [authToken]); // re-fetch projects if the token changes

    if (error) {
        return <div>{error}</div>;
    }

    if (!projects.length) {
        return <div>No projects available.</div>; // handle empty array
    }

    return (
        <div>
            <h1>Dashboard</h1>
            <ul>
                {projects.map((project) => (
                    <li key={project.id}>
                        <h2>{project.title}</h2>
                        <p>{project.description}</p>
                        <p>Created by: {project.createdBy}</p>
                        <p>Created on: {project.creationDate}</p>
                    </li>
                ))}
            </ul>
        </div>
    );
};

export default Dashboard;