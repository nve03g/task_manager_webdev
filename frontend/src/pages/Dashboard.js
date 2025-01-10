import { Popover, OverlayTrigger, Button } from 'react-bootstrap'; // import this one before bootstrap (says the documentation)
import 'bootstrap/dist/css/bootstrap.min.css';

import React, { useState, useEffect } from 'react';
import { useAuth } from '../AuthContext';
import { data, useNavigate } from 'react-router-dom';
import '../styles/dashboard.css';

const Dashboard = () => {
    const [projects, setProjects] = useState([]);
    const [error, setError] = useState(null);
    const { authToken } = useAuth(); // access the authentication token from the AuthContext
    const navigate = useNavigate();

    useEffect(() => {
        // fetch projects and tasks from backend
        const fetchDashboardData = async () => {
            try {
                // fetch projects and their tasks (only those assigned to user)
                const response = await fetch('https://localhost:443/projects-with-tasks', {
                    headers: {
                        Authorization: `Bearer ${authToken}`, // send token in Authorization header
                        // Authorization: `Bearer ${localStorage.getItem("token")}`, // send token in Authorization header
                    },
                });

                const data = await response.json();
                console.log('API response:', data);

                if (!response.ok) {
                    throw new Error(data.error || 'Failed to fetch data');
                }

                setProjects(data.projects || []);
            } catch (error) {
                console.error('Error fetching projects:', error);
                setError('Failed to load projects. Please try again.');
            }
        };

        fetchDashboardData();
    }, []); // re-fetch projects if the token changes

    if (error) {
        return <div className='alert alert-danger'>{error}</div>;
    }

    if (!projects.length) {
        return <div className='alert alert-info'>No projects available. Create one to get started!</div>; // handle empty array
    }

    return (
        <div className="container mt-4">
            <h1 className="mb-4">Dashboard</h1>
            <div className="row">
                {projects.map((project) => (
                    <div key={project.projectID} className="col-md-6 mb-4">
                        <div className="card h-100">
                            <div className="card-body">
                                <h5 className="card-title">{project.title}</h5>
                                <p className="card-text">{project.description}</p>
                                <p className="text-muted">
                                    Created by {project.createdBy} on{' '}
                                    {new Date(project.creationDate).toLocaleDateString()}
                                </p>
                                <h6>Tasks</h6>
                                {project.tasks.length > 0 ? (
                                    <ul className="list-group">
                                        {project.tasks.map((task) => (
                                            <li key={task.taskID} className="list-group-item d-flex justify-content-between align-items-center">
                                                <span>{task.name}</span>
                                                <span className="badge bg-primary">{task.status}</span>
                                            </li>
                                        ))}
                                    </ul>
                                ) : (
                                    <p>No tasks available.</p>
                                )}
                            </div>
                            <div className="card-footer d-flex justify-content-between">
                                <button
                                    className="btn btn-primary"
                                    onClick={() => navigate(`/add-task/${project.projectID}`)}
                                >
                                    Add Task
                                </button>
                                <button
                                    className="btn btn-secondary"
                                    onClick={() => navigate(`/edit-project/${project.projectID}`)}
                                >
                                    Edit Project
                                </button>
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default Dashboard;