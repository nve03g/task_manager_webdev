import React, { useState, useEffect } from 'react';
import { useAuth } from '../AuthContext';
import '../styles/profile.css';

const Profile = () => {
    const [profile, setProfile] = useState(null);
    const [error, setError] = useState(null);
    const { authToken } = useAuth(); // access the auth token from the AuthContext

    useEffect(() => {
        const fetchProfile = async () => {
            try {
                const response = await fetch('https://localhost:443/profile', {
                    headers: {
                        Authorization: `Bearer ${authToken}`, // send token in Authorization header
                    },
                });

                if (!response.ok) {
                    throw new Error('Failed to fetch profile');
                }

                const data = await response.json();
                setProfile(data); // assuming the API returns user profile data
            } catch (error) {
                console.error('Error fetching profile:', error);
                setError('Failed to load profile. Please try again.');
            }
        };

        fetchProfile();
    }, [authToken]); // re-fetch profile if the token changes

    if (error) {
        return <div>{error}</div>;
    }

    if (!profile) {
        return <div>Loading...</div>;
    }

    return (
        <div className="profile-container">
            <h1 className="profile-header">Profile</h1>
            <h2 className="profile-welcome">
                Hello, <span className="username">{profile.username}</span>! You have <span className="task-count">{profile.assignedTasksCount}</span> {profile.assignedTasksCount === 1 ? "task" : "tasks"} left to do :)
            </h2>

            <div className="projects-section">
                <div className="projects-group">
                    <h3 className="projects-title">Created Projects:</h3>
                    {profile.createdProjects.length > 0 ? (
                        <ul className="projects-list">
                            {profile.createdProjects.map((project) => (
                                <li key={project.id} className="project-item">
                                    {project.title}
                                </li>
                            ))}
                        </ul>
                    ) : (
                        <p className="no-projects">You haven't created any projects yet.</p>
                    )}
                </div>

                <div className="projects-group">
                    <h3 className="projects-title">Assigned Projects:</h3>
                    {profile.assignedProjects.length > 0 ? (
                        <ul className="projects-list">
                            {profile.assignedProjects.map((project) => (
                                <li key={project.id} className="project-item">
                                    {project.title}
                                </li>
                            ))}
                        </ul>
                    ) : (
                        <p className="no-projects">You're currently not assigned to any projects.</p>
                    )}
                </div>
            </div>
        </div>

    );
};

export default Profile;