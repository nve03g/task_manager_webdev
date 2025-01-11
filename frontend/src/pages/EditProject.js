import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { jwtDecode } from 'jwt-decode'; // to extract user ID from token
import { useAuth } from '../AuthContext';
import '../styles/addProject.css';

const EditProject = () => {
    const { projectId } = useParams(); // get the project ID from route params
    const { authToken } = useAuth();
    const [isAdmin, setIsAdmin] = useState(false);
    const [createdBy, setCreatedBy] = useState(null);
    const [error, setError] = useState(null);
    const [title, setTitle] = useState('');
    const [description, setDescription] = useState('');
    const [alreadyAssignedUsers, setAlreadyAssignedUsers] = useState([]); // users already assigned to the project
    const [newlyAssignedUsers, setNewlyAssignedUsers] = useState([{ userId: '', role: 'general' }]); // users newly assigned to the project
    const [useNoDescription, setUseNoDescription] = useState(false);
    const [users, setUsers] = useState([]); // list of all users from the database
    const [message, setMessage] = useState(null);
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

    // fetch project details to pre-fill fields
    useEffect(() => {
        const fetchProjectDetails = async () => {
            try {
                // decode the token to get the current user ID
                const decodedToken = jwtDecode(authToken);
                const currentUserId = decodedToken.id;

                const response = await fetch(`https://localhost:443/projects/${projectId}`, {
                    headers: { Authorization: `Bearer ${authToken}` },
                });
                const data = await response.json();
                console.log('Project data:', data);
                if (response.ok) {
                    setTitle(data.project.title || '');
                    setDescription(data.project.description || '');
                    setUseNoDescription(data.project.description === 'No Description');
                    setAlreadyAssignedUsers(
                        data.assignedUsers.map((user) => ({
                            userId: user.userID,
                            role: user.role,
                        }))
                    );
                    setCreatedBy(data.project.createdBy); // store the original admin ID

                    // check if the current user is an admin in the project
                    const currentUserRole = data.assignedUsers.find(
                        (user) => user.userID === currentUserId
                    )?.role;
                    setIsAdmin(currentUserRole === 'admin');
                } else {
                    throw new Error(data.error || 'Failed to fetch project details.');
                }
            } catch (err) {
                console.error('Error fetching project details:', err);
                setError('An error occurred while fetching project details.');
            }
        };

        fetchProjectDetails();
    }, [authToken, projectId]);

    // redirect or show a message if the user is not an admin in the project
    if (!isAdmin) {
        return <div className="alert alert-danger">You do not have permission to edit this project.</div>;
    }

    // for already assigned users
    const handleAlreadyAssignedUserChange = (index, field, value) => {
        const updatedUsers = [...alreadyAssignedUsers];
        if (field === 'role' && updatedUsers[index].userId === createdBy) {
            setError('Cannot modify the role of the project creator.');
            return;
        }
        updatedUsers[index][field] = value;
        setAlreadyAssignedUsers(updatedUsers);
    };

    const handleRemoveAlreadyAssignedUser = async (userId) => {
        if (window.confirm('Are you sure you want to remove this user from the project?')) {
            try {
                const response = await fetch(`https://localhost:443/projects/${projectId}/users/${userId}`,
                    {
                        method: 'DELETE',
                        headers: {
                            'Content-Type': 'application/json',
                            Authorization: `Bearer ${authToken}`,
                        },
                    }
                );

                const data = await response.json();
                if (response.ok) {
                    setMessage(data.message || 'User removed successfully!');
                    setAlreadyAssignedUsers((prev) =>
                        prev.filter((user) => user.userId !== userId));
                } else {
                    setError(data.error || 'Failed to remove user from project.');
                }
            } catch (err) {
                console.error('Error removing user:', err);
                setError('An error occurred whilt removing the user.');
            }
        }
    };

    // for newly assigned users
    const handleNewAssignedUserChange = (index, field, value) => {
        const updatedUsers = [...newlyAssignedUsers];
        updatedUsers[index][field] = value;
        setNewlyAssignedUsers(updatedUsers);
    };

    const handleAddNewAssignedUser = () => {
        setNewlyAssignedUsers([...newlyAssignedUsers, { userId: '', role: 'general' }]);
    };

    const handleRemoveNewAssignedUser = (index) => {
        setNewlyAssignedUsers(newlyAssignedUsers.filter((_, i) => i !== index));
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

            // filter out users with empty IDs
            const allAssignedUsers = [
                ...alreadyAssignedUsers,
                ...newlyAssignedUsers.filter((user) => user.userId)
            ];

            const response = await fetch(`https://localhost:443/projects/${projectId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${authToken}`
                },
                body: JSON.stringify({
                    title,
                    description: useNoDescription ? 'No Description' : description,
                    users: allAssignedUsers,
                }),
            });

            const data = await response.json();

            if (response.ok) {
                setError(null);
                setMessage('Project updated successfully!');
                setTimeout(() => navigate('/dashboard'), 2000);
            } else {
                setMessage(null);
                setError(data.error || 'Failed to update project.');
            }
        } catch (err) {
            setMessage(null);
            setError('An error occurred. Please try again.');
        }
    };

    // for deleting the project
    const handleDeleteProject = async () => {
        if (window.confirm('Are you sure you want to delete this project? This action cannot be undone.')) {
            try {
                const response = await fetch(`https://localhost:443/projects/${projectId}`, {
                    method: 'DELETE',
                    headers: {
                        Authorization: `Bearer ${authToken}`,
                    },
                });

                const data = await response.json();

                if (response.ok) {
                    setMessage(data.message || 'Project deleted successfully.');
                    setTimeout(() => navigate('/dashboard'), 2000);
                } else {
                    setError(data.error || 'Failed to delete project.');
                }
            } catch (err) {
                console.error('Error deleting project:', err);
                setError('An error occurred while deleting the project.');
            }
        }
    };

    return (
        <div className="add-project-container container mt-4">
            <h1>Edit Project</h1>
            {message && !error && <p className="success-message">{message}</p>}
            {error && <p className="error-message">{error}</p>}
            <form onSubmit={handleSubmit}>
                {/* Project Title */}
                <div className="form-group mb-3">
                    <label htmlFor="title">Project Title</label>
                    <input
                        type="text"
                        id="title"
                        value={title}
                        onChange={(e) => setTitle(e.target.value)}
                        className="form-control"
                        required
                        disabled={!isAdmin} // Disable editing for non-admins
                    />
                </div>

                {/* Project Description */}
                <div className="form-group mb-3">
                    <label htmlFor="description">Project Description</label>
                    <textarea
                        id="description"
                        value={useNoDescription ? '' : description}
                        onChange={(e) => setDescription(e.target.value)}
                        className="form-control"
                        disabled={!isAdmin || useNoDescription} // Disable for non-admins or "No Description"
                        placeholder="Write your project description here"
                    />
                    <div className="form-check mt-2">
                        <label>
                            <input
                                type="checkbox"
                                id="noDescription"
                                className="form-check-input"
                                checked={useNoDescription}
                                onChange={(e) => setUseNoDescription(e.target.checked)}
                                disabled={!isAdmin} // Disable for non-admins
                            />
                        </label>
                        <label htmlFor="noDescription" className="form-check-label">
                            No Description
                        </label>
                    </div>
                </div>

                {/* Assign New Users */}
                <div className="form-group mb-3">
                    <label>(Re)assign Users</label>
                    {newlyAssignedUsers.map((user, index) => (
                        <div key={index} className="d-flex gap-2 align-items-center mb-2">
                            <select
                                value={user.userId}
                                onChange={(e) => handleNewAssignedUserChange(index, 'userId', e.target.value)}
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
                                onChange={(e) => handleNewAssignedUserChange(index, 'role', e.target.value)}
                                className="form-select"
                            >
                                <option value="general">General</option>
                                <option value="admin">Admin</option>
                            </select>
                            <button
                                type="button"
                                onClick={() => handleRemoveNewAssignedUser(index)}
                                className="btn btn-danger"
                            >
                                Remove
                            </button>
                        </div>
                    ))}
                    <button type="button" onClick={handleAddNewAssignedUser} className="btn btn-secondary mt-2">
                        Add User
                    </button>
                </div>

                {/* Display current assigned users */}
                <div className="mt-4">
                    <h5>Current Assigned Users:</h5>
                    <ul className="list-group">
                        {alreadyAssignedUsers.map((user, index) => {
                            // match user by converting both ID's to strings
                            const matchedUser = users.find((u) => String(u.userID) === String(user.userId));
                            return (
                                <li key={user.userId || index} className="list-group-item d-flex align-items-center justify-content-between">
                                    {/* Username */}
                                    <div className='user-name'>
                                        <strong>{matchedUser ? matchedUser.username : 'Unknown User'}</strong>
                                    </div>
                                    {/* Role */}
                                    <div className='user-role'>
                                        <span className="text-muted">{user.role}</span>
                                    </div>
                                    {/* Remove Button */}
                                    {isAdmin && user.userId !== createdBy && (
                                        <div className='remove-button'>
                                            <button
                                                type="button"
                                                onClick={() => handleRemoveAlreadyAssignedUser(user.userId)}
                                                className="btn btn-danger btn-sm"
                                            >
                                                Remove
                                            </button>
                                        </div>
                                    )}
                                </li>
                            );
                        })}
                    </ul>
                </div>

                {/* Save Changes */}
                <button type="submit" className="btn btn-primary" disabled={!isAdmin}>
                    Save Changes
                </button>

                {/* Delete Project */}
                <div className='mt-4'>
                    {isAdmin && (
                        <button
                            type="button"
                            onClick={handleDeleteProject}
                            className="btn btn-danger"
                        >
                            Delete Project
                        </button>
                    )}
                </div>
            </form>
        </div>
    );

};

export default EditProject;
