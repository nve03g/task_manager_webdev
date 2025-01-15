import React, { useState, useEffect } from 'react';
import { useAuth } from '../AuthContext';

const EditTask = ({ taskId, projectId, onTaskUpdated, onClose }) => {
    const { authToken } = useAuth();
    const [taskName, setTaskName] = useState('');
    const [taskDescription, setTaskDescription] = useState('');
    const [status, setStatus] = useState('');
    const [error, setError] = useState('');
    const [message, setMessage] = useState('');

    // fetch task details to pre-fill the form
    useEffect(() => {
        const fetchTaskDetails = async () => {
            try {
                const response = await fetch(`https://localhost:443/projects/${projectId}/tasks/${taskId}`, {
                    method: 'GET',
                    headers: {
                        Authorization: `Bearer ${authToken}`,
                    },
                });

                const data = await response.json();

                if (response.ok) {
                    setTaskName(data.name);
                    setTaskDescription(data.description || '');
                    setStatus(data.status || 'Pending');
                } else {
                    setError(data.error || 'Failed to fetch task details.');
                }
            } catch (err) {
                setError('An error occurred while fetching task details.');
            }
        };

        fetchTaskDetails();
    }, [taskId, projectId, authToken]);

    const handleSubmit = async (e) => {
        e.preventDefault();

        const updatedTask = { name: taskName, description: taskDescription, status };

        try {
            const response = await fetch(`https://localhost:443/projects/${projectId}/tasks/${taskId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${authToken}`,
                },
                body: JSON.stringify(updatedTask),
            });

            if (response.ok) {
                onTaskUpdated(); // callback to refresh task list
                onClose(); // close the popover
            } else {
                const errorData = await response.json();
                setError(errorData.message || 'Failed to update task.');
            }
        } catch (err) {
            console.error('Error updating task:', err);
            setError('An error occurred while updating the task.');
        }
    };

    const handleDelete = async () => {
        if (window.confirm('Are you sure you want to delete this task? This action cannot be undone.')) {
            try {
                const response = await fetch(`https://localhost:443/projects/${projectId}/tasks/${taskId}`, {
                    method: 'DELETE',
                    headers: {
                        Authorization: `Bearer ${authToken}`,
                    },
                });

                const data = await response.json();

                if (response.ok) {
                    setMessage('Task deleted successfully.');
                    setTimeout(() => {
                        onTaskUpdated();
                        onClose();
                    }, 1000);
                } else {
                    setError(data.error || 'Failed to delete task.');
                }
            } catch (err) {
                console.error('Error Deleting Task:', err);
                setError('An error occurred while deleting the task.');
            }
        }
    };

    return (
        <div className="popover-content">
            <h5>Edit Task</h5>
            {message && <p className='success-message text-success'>{message}</p>}
            {error && <p className="error-message text-danger">{error}</p>}
            <form onSubmit={handleSubmit}>
                <div className="form-group">
                    <label>Task Name</label>
                    <input
                        type="text"
                        value={taskName}
                        onChange={(e) => setTaskName(e.target.value)}
                        className="form-control"
                        required
                    />
                </div>
                <div className="form-group">
                    <label>Task Description</label>
                    <textarea
                        value={taskDescription}
                        onChange={(e) => setTaskDescription(e.target.value)}
                        className="form-control"
                    ></textarea>
                </div>
                <div className="form-group">
                    <label>Status</label>
                    <select
                        value={status}
                        onChange={(e) => setStatus(e.target.value)}
                        className="form-control"
                        required
                    >
                        <option value="Pending">Pending</option>
                        <option value="In Progress">In Progress</option>
                        <option value="Urgent">Urgent</option>
                        <option value="Complete">Complete</option>
                        <option value="Not Started">Not Started</option>
                    </select>
                </div>
                <button type="submit" className="btn btn-primary mt-2">
                    Save Changes
                </button>
            </form>
            <button
                className="btn btn-danger mt-3"
                onClick={handleDelete}
            >
                Delete Task
            </button>
        </div>
    );
};

export default EditTask;
