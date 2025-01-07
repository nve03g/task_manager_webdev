import React, { useState, useEffect } from 'react';
import { useAuth } from '../AuthContext';
import Navbar from '../components/Navbar';
// import './Profile.css';

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
        <div>
            <h1>Profile</h1>
            <h2>Username: {profile.username}</h2>
            <h3>Created Projects:</h3>
            <ul>
                {profile.createdProjects.map((project) => (
                    <li key={project.id}>
                        {project.title} (Created on: {project.creationDate})
                    </li>
                ))}
            </ul>
            <h3>Assigned Projects:</h3>
            <ul>
                {profile.assignedProjects.map((project) => (
                    <li key={project.id}>{project.title}</li>
                ))}
            </ul>
            <h3>Tasks Assigned:</h3>
            <p>{profile.assignedTasksCount} tasks assigned.</p>
        </div>
    );
};

export default Profile;