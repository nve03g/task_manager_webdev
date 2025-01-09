import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import '../styles/addProject.css';

const AddProject = () => {
    const [title, setTitle] = useState('');
    const [description, setDescription] = useState('');
    const [users, setUsers] = useState([]); // list of all users from the database
    const [assignedUsers, setAssignedUsers] = useState([{ userId: '', role: 'general' }]); // users assigned to the project
    const [message, setMessage] = useState(null);
    const [error, setError] = useState(null);
    const { authToken } = useAuth();
    const navigate = useNavigate();

    // fetch users from the backend
    useEffect(() => {
        const fetchUsers = async () => {
            try {
                const response = await fetch('https://localhost:443/users', {
                    headers: {
                        Authorization: `Bearer ${authToken}`,
                    },
                });
                const data = await response.json();
                if (response.ok) {
                    setUsers(data.users || []); // set all users in dropdown
                } else {
                    setError(data.error || 'Failed to fetch users.');
                }
            } catch (err) {
                setError('An error occurred while fetching users.');
            }
        };

        fetchUsers();
    }, [authToken]);

    const handleAssignedUserChange = (index, field, value) => {
        const updatedAssignedUsers = [...assignedUsers];
        updatedAssignedUsers[index][field] = value;
        setAssignedUsers(updatedAssignedUsers);
    };

    const handleAddAssignedUser = () => {
        setAssignedUsers([...assignedUsers, { userId: '', role: 'general' }]);
    };

    const handleRemoveAssignedUser = (index) => {
        setAssignedUsers(assignedUsers.filter((_, i) => i !== index));
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
                body: JSON.stringify({ title, description, users: assignedUsers }),
            });

            const data = await response.json();

            if (response.ok) {
                setMessage('Project created successfully!');
                setTimeout(() => navigate('/dashboard'), 2000);
            } else {
                setError(data.error || 'Failed to create project.');
            }

            // setMessage('Project created successfully!');
            // console.log('Submitted data:', { title, description, users: selectedUsers });
            // setTimeout(() => navigate('/dashboard'), 2000); // redirect to dashboard after 2 seconds
        } catch (err) {
            setError('An error occurred. Please try again.');
        }
    };

    return (
        <div className="add-project-container">
            <h1>Create New Project</h1>
            {message && <p className="success-message">{message}</p>}
            {error && <p className="error-message">{error}</p>}
            <form onSubmit={handleSubmit}>
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
                    {assignedUsers.map((user, index) => (
                        <div key={index} className="user-entry">
                            <select
                                value={user.userId}
                                onChange={(e) =>
                                    handleAssignedUserChange(index, 'userId', e.target.value)
                                }
                            >
                                <option value="">Select a user</option>
                                {users.map((userOption) => (
                                    <option key={userOption.userID} value={userOption.userID}>
                                        {userOption.username}
                                    </option>
                                ))}
                            </select>
                            <select
                                value={user.role}
                                onChange={(e) =>
                                    handleAssignedUserChange(index, 'role', e.target.value)
                                }
                            >
                                <option value="general">General</option>
                                <option value="admin">Admin</option>
                            </select>
                            <button
                                type="button"
                                onClick={() => handleRemoveAssignedUser(index)}
                                disabled={assignedUsers.length === 1}
                            >
                                Remove
                            </button>
                        </div>
                    ))}
                    <button type="button" onClick={handleAddAssignedUser}>
                        Add User
                    </button>
                </div>
                <button type="submit" className="submit-button">
                    Create Project
                </button>
            </form>
        </div>
    );
};

export default AddProject;
