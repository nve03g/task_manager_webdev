import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import '../styles/addProject.css';

const AddProject = () => {
    const [title, setTitle] = useState('');
    const [description, setDescription] = useState('');
    const [users, setUsers] = useState([{ userId: '', role: 'general' }]); // Default user entry
    const [message, setMessage] = useState(null);
    const [error, setError] = useState(null);
    const { authToken } = useAuth(); // access the authentication token from the AuthContext
    const navigate = useNavigate();

    const handleUserChange = (index, field, value) => {
        const updatedUsers = [...users];
        updatedUsers[index][field] = value;
        setUsers(updatedUsers);
    };

    const handleAddUser = () => {
        setUsers([...users, { userId: '', role: 'general' }]);
    };

    const handleRemoveUser = (index) => {
        const updatedUsers = users.filter((_, i) => i !== index);
        setUsers(updatedUsers);
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        try {
            const response = await fetch('https://localhost:443/projects', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${authToken}`
                },
                body: JSON.stringify({ title, description, users }),
            });

            const data = await response.json();

            if (!response.ok) {
                setError(data.error || 'Failed to create project.');
                return;
            }

            setMessage('Project created successfully!');
            setTimeout(() => navigate('/dashboard'), 2000); // Redirect to dashboard after 2 seconds
        } catch (err) {
            setError('An error occurred. Please try again.');
        }
    };

    return (
        <div className="add-project-container">
            <h1>Create New Project</h1>
            {message && <p className="success-message">{message}</p>}
            {error && <p className="error-message">{error}</p>}
            <form onSubmit={handleSubmit} className="add-project-form">
                <div className="form-group">
                    <label htmlFor="title">Project Title</label>
                    <input
                        type="text"
                        id="title"
                        value={title}
                        onChange={(e) => setTitle(e.target.value)}
                        required
                    />
                </div>
                <div className="form-group">
                    <label htmlFor="description">Project Description</label>
                    <textarea
                        id="description"
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                        required
                    />
                </div>
                <div className="form-group">
                    <label>Assign Users</label>
                    {users.map((user, index) => (
                        <div key={index} className="user-entry">
                            <input
                                type="text"
                                placeholder="User ID"
                                value={user.userId}
                                onChange={(e) => handleUserChange(index, 'userId', e.target.value)}
                                required
                            />
                            <select
                                value={user.role}
                                onChange={(e) => handleUserChange(index, 'role', e.target.value)}
                            >
                                <option value="admin">Admin</option>
                                <option value="general">General</option>
                            </select>
                            <button
                                type="button"
                                onClick={() => handleRemoveUser(index)}
                                disabled={users.length === 1}
                            >
                                Remove
                            </button>
                        </div>
                    ))}
                    <button type="button" onClick={handleAddUser}>
                        Add User
                    </button>
                </div>
                <button type="submit" className="submit-button">Create Project</button>
            </form>
        </div>
    );
};

export default AddProject;
