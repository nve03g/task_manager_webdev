import React, { useState, useEffect } from 'react';
import { useAuth } from '../AuthContext';
import { useNavigate, useParams } from 'react-router-dom';

const AddTask = () => {
  const { projectId } = useParams(); // fetch projectId from url
  const { authToken } = useAuth();
  const [taskName, setTaskName] = useState('');
  const [taskDescription, setTaskDescription] = useState('');
  const [status, setStatus] = useState('Pending');
  const [users, setUsers] = useState([]);
  const [assignedUsers, setAssignedUsers] = useState([{ userId: '' }]); // list of assigned users
  const [error, setError] = useState('');
  const navigate = useNavigate();

  // dropdown: fetch users for current project from backend
  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const response = await fetch(`https://localhost:443/projects/${projectId}/users`, {
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${authToken}`,
          },
        });

        const data = await response.json();
        console.log('Fetched users:', data);

        if (response.ok) {
          const formattedUsers = data.map(user => ({
            id: user.userID,
            name: user.username,
          }));
          setUsers(formattedUsers || []);
        } else {
          setError(data.error || 'Failed to fetch users.');
        }
      } catch (err) {
        setError('An error occurred while fetching users.');
      }
    };

    fetchUsers();
  }, [projectId, authToken]);


  const handleAssignedUserChange = (index, field, value) => {
    const updatedAssignedUsers = [...assignedUsers];
    updatedAssignedUsers[index][field] = value;
    setAssignedUsers(updatedAssignedUsers);
  };

  const handleAddAssignedUser = () => {
    setAssignedUsers([...assignedUsers, { userId: '' }]);
  };

  const handleRemoveAssignedUser = (index) => {
    setAssignedUsers(assignedUsers.filter((_, i) => i !== index));
  };


  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!taskName || !status || assignedUsers.length === 0 || assignedUsers.some((user) => !user.userId)) {
      setError('Please fill in taskname, give the task a status and assign at least one user.');
      return;
    }

    const taskData = {
      name: taskName,
      status,
      description: taskDescription || '', // optional description
      assignedUserIds: assignedUsers.map((user) => Number(user.userId)),
      // createdBy: user.username,
      // projectId,
      // createdAt: new Date().toISOString(),
    };

    try {
      const response = await fetch(`https://localhost:443/projects/${projectId}/tasks`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify(taskData),
      });

      if (response.ok) {
        navigate(`/dashboard`);
      } else {
        const errorData = await response.json();
        setError(errorData.message || 'Failed to create task.');
      }
    } catch (err) {
      setError('An error occurred. Please try again later.');
    }
  };


  return (
    <>
      <div className="container mt-4">
        <h1>Add Task</h1>
        {error && <p className="error-message">{error}</p>}
        <form onSubmit={handleSubmit}>
          <div className="form-group mb-3">
            <label htmlFor="taskName">Task Name</label>
            <input
              type="text"
              id="taskName"
              value={taskName}
              onChange={(e) => setTaskName(e.target.value)}
              className="form-control"
              required
            />
          </div>
          <div className="form-group mb-3">
            <label htmlFor="taskDescription">Task Description (Optional)</label>
            <textarea
              id="taskDescription"
              value={taskDescription}
              onChange={(e) => setTaskDescription(e.target.value)}
              className="form-control"
            />
          </div>
          <div className="form-group mb-3">
            <label htmlFor="status">Status</label>
            <select
              id="status"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="form-control"
              required
            >
              <option value="Pending">Pending</option>
              <option value="In Progress">In Progress</option>
              <option value="Completed">Completed</option>
            </select>
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
                    <option key={userOption.id} value={userOption.id}>
                      {userOption.name}
                    </option>
                  ))}
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
            Add Task
          </button>
        </form>
      </div>
    </>
  );
};

export default AddTask;