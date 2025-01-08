import React, { useState, useEffect } from 'react';
import Navbar from '../components/Navbar';
import { useAuth } from '../AuthContext';
import { data, useNavigate } from 'react-router-dom';
// import './Dashboard.css';

const Dashboard = () => {
    const [projects, setProjects] = useState([]);
    const [error, setError] = useState(null);
    // const [loading, setLoading] = useState(true);
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

                // // fetch tasks
                // const taskResponse = await fetch('https://localhost:443/tasks', {
                //     headers: {
                //         Authorization: `Bearer ${authToken}`, // send token in Authorization header
                //         // Authorization: `Bearer ${localStorage.getItem("token")}`, // send token in Authorization header
                //     },
                // });

                const data = await response.json();
                // const taskData = await taskResponse.json();
                console.log('API response:', data);

                if (!response.ok) {
                    throw new Error(data.error || 'Failed to fetch data');
                }
                // if (!taskResponse.ok) {
                //     throw new Error(taskData.error || 'Failed to fetch tasks');
                // }

                // setProjects(Array.isArray(data.projects) ? data.projects : []); // this ensures that projects is always an array
                setProjects(data.projects || []);
                // setTasks(taskData.tasks || []);
            } catch (error) {
                console.error('Error fetching projects:', error);
                setError('Failed to load projects. Please try again.');
            }
            // finally {
            //     setLoading(false);
            // }
        };

        fetchDashboardData();
    }, []); // re-fetch projects if the token changes

    if (error) {
        return <div>{error}</div>;
    }

    if (!projects.length) {
        return <div>No projects available.</div>; // handle empty array
    }
    // if (!tasks.length) {
    //     return <div>No tasks available.</div>; // handle empty array
    // }


    return (
        <div className="dashboard-container">
            <h1>Dashboard</h1>

            <div className="dashboard-actions">
                {/* <button onClick={() => navigate("/add-project")} className="action-button">
                    Add Project
                </button> */}
                <button onClick={() => navigate("/add-task")} className="action-button">
                    Add Task
                </button>
            </div>

            <div className="dashboard-content">
                {projects.map(project => (
                    <div key={project.projectID} className="project-section">
                        <h2>{project.title}</h2>
                        <p>Created by: {project.createdBy}</p>
                        <p>Created on: {new Date(project.creationDate).toLocaleDateString()}</p>
                        <p>{project.description}</p>

                        <div className="tasks-section">
                            <h3>Tasks</h3>
                            {project.tasks.length > 0 ? (
                                <ul>
                                    {project.tasks.map(task => (
                                        <li key={task.taskID}>
                                            <h4>{task.name}</h4>
                                            <p>Status: {task.status}</p>
                                            <p>{task.description}</p>
                                        </li>
                                    ))}
                                </ul>
                            ) : (
                                <p>No tasks in this project.</p>
                            )}
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );

    // return (
    //     <div className="dashboard-container">
    //       <h1>Dashboard</h1>

    //       <div className="dashboard-actions">
    //         <button onClick={() => navigate("/add-project")} className="action-button">
    //           Add Project
    //         </button>
    //         <button onClick={() => navigate("/add-task")} className="action-button">
    //           Add Task
    //         </button>
    //       </div>

    //       <div className="dashboard-content">
    //         <div className="projects-section">
    //           <h2>Your Projects</h2>
    //           {projects.length > 0 ? (
    //             <ul>
    //               {projects.map((project) => (
    //                 <li key={project.projectID}>
    //                   <h3>{project.title}</h3>
    //                   <p>Created by: {project.createdBy}</p>
    //                   <p>Created on: {new Date(project.creationDate).toLocaleDateString()}</p>
    //                 </li>
    //               ))}
    //             </ul>
    //           ) : (
    //             <p>No projects available. Start by creating one!</p>
    //           )}
    //         </div>

    //         <div className="tasks-section">
    //           <h2>Your Tasks</h2>
    //           {tasks.length > 0 ? (
    //             <ul>
    //               {tasks.map((task) => (
    //                 <li key={task.taskID}>
    //                   <h3>{task.name}</h3>
    //                   <p>Project: {task.projectTitle}</p>
    //                   <p>Status: {task.status}</p>
    //                   <p>{task.description}</p>
    //                 </li>
    //               ))}
    //             </ul>
    //           ) : (
    //             <p>No tasks assigned yet.</p>
    //           )}
    //         </div>
    //       </div>
    //     </div>
    //   );
};

export default Dashboard;