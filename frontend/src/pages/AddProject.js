import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import '../styles/addProject.css';

const AddProject = () => {
    const [title, setTitle] = useState('');
    const [description, setDescription] = useState('');
    const [useNoDescription, setUseNoDescription] = useState(false); // State for "No Description"
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

        // validate description if "no description" is not selected
        if (!useNoDescription && description.trim() === '') {
            setMessage(null);
            setError('Please enter a description for the project.');
            return; // stop submission if description is empty
        }

        try {
            setError(null); // clear previous error (if any)

            const response = await fetch('https://localhost:443/projects', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${authToken}`
                },
                body: JSON.stringify({
                    title,
                    description: useNoDescription ? 'No Description' : description,
                    users: assignedUsers
                }),
            });

            const data = await response.json();

            if (response.ok) {
                setError(null);
                setMessage('Project created successfully!');
                setTimeout(() => navigate('/dashboard'), 2000);
            } else {
                setMessage(null);
                setError(data.error || 'Failed to create project.');
            }
        } catch (err) {
            setMessage(null);
            setError('An error occurred. Please try again.');
        }
    };

    return (
        <div className="add-project-container container mt-4">
            <h1>Create New Project</h1>
            {message && !error && <p className="success-message">{message}</p>}
            {error && <p className="error-message">{error}</p>}
            <form onSubmit={handleSubmit}>
                <div className="form-group mb-3">
                    <label htmlFor="title">Project Title</label>
                    <input
                        type="text"
                        id="title"
                        value={title}
                        onChange={(e) => setTitle(e.target.value)}
                        className="form-control"
                        required
                    />
                </div>
                <div className="form-group mb-3">
                    <label htmlFor="description">Project Description</label>
                    <textarea
                        id="description"
                        value={useNoDescription ? '' : description}
                        onChange={(e) => setDescription(e.target.value)}
                        className="form-control"
                        disabled={useNoDescription} // Disable textarea if "No Description" is selected
                        placeholder="Write your project description here"
                    />
                    <div className="form-check mt-2">
                        {/* <label>No Description</label> */}
                        <label>
                            <input
                                type="checkbox"
                                id="noDescription"
                                name="myCheckBox"
                                className="form-check-input"
                                checked={useNoDescription}
                                onChange={(e) => setUseNoDescription(e.target.checked)}
                            />
                        </label>

                        <label htmlFor="noDescription" className="form-check-label">
                            No Description
                        </label>
                    </div>
                </div>
                <div className="form-group mb-3">
                    <label>Assign Users</label>
                    {assignedUsers.map((user, index) => (
                        <div key={index} className="d-flex gap-2 align-items-center mb-2">
                            <select
                                value={user.userId}
                                onChange={(e) => handleAssignedUserChange(index, 'userId', e.target.value)}
                                className="form-select"
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
                                onChange={(e) => handleAssignedUserChange(index, 'role', e.target.value)}
                                className="form-select"
                            >
                                <option value="general">General</option>
                                <option value="admin">Admin</option>
                            </select>
                            <button
                                type="button"
                                onClick={() => handleRemoveAssignedUser(index)}
                                className="btn btn-danger"
                                disabled={assignedUsers.length === 1}
                            >
                                Remove
                            </button>
                        </div>
                    ))}
                    <button type="button" onClick={handleAddAssignedUser} className="btn btn-secondary mt-2">
                        Add User
                    </button>
                </div>
                <button type="submit" className="btn btn-primary">
                    Create Project
                </button>
            </form>
        </div>
    );
};

export default AddProject;
