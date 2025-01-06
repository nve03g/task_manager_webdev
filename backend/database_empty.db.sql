BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "User" (
	"userID"	INTEGER NOT NULL UNIQUE,
	"username"	TEXT NOT NULL UNIQUE,
	"password"	INTEGER NOT NULL,
	PRIMARY KEY("userID" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "Project" (
	"projectID"	INTEGER NOT NULL UNIQUE,
	"title"	TEXT NOT NULL UNIQUE,
	"description"	TEXT,
	"creationDate"	TEXT NOT NULL,
	"createdBy"	INTEGER NOT NULL,
	PRIMARY KEY("projectID" AUTOINCREMENT),
	FOREIGN KEY("createdBy") REFERENCES "User"("userID")
);
CREATE TABLE IF NOT EXISTS "Task" (
	"taskID"	INTEGER NOT NULL UNIQUE,
	"name"	TEXT NOT NULL,
	"status"	TEXT NOT NULL,
	"description"	TEXT,
	"creationDate"	TEXT NOT NULL,
	"createdBy"	INTEGER NOT NULL,
	"projectID"	INTEGER NOT NULL,
	PRIMARY KEY("taskID" AUTOINCREMENT),
	FOREIGN KEY("createdBy") REFERENCES "User"("userID"),
	FOREIGN KEY("projectID") REFERENCES "Project"("projectID")
);
CREATE TABLE IF NOT EXISTS "Task_User" (
	"task_X_user_ID"	INTEGER NOT NULL UNIQUE,
	"taskID"	INTEGER NOT NULL,
	"userID"	INTEGER NOT NULL,
	PRIMARY KEY("task_X_user_ID" AUTOINCREMENT),
	FOREIGN KEY("userID") REFERENCES "User"("userID"),
	FOREIGN KEY("taskID") REFERENCES "Task"("taskID")
);
CREATE TABLE IF NOT EXISTS "Project_User" (
	"project_X_user_ID"	INTEGER NOT NULL UNIQUE,
	"projectID"	INTEGER NOT NULL,
	"userID"	INTEGER NOT NULL,
	"role"	TEXT NOT NULL,
	PRIMARY KEY("project_X_user_ID" AUTOINCREMENT),
	FOREIGN KEY("projectID") REFERENCES "Project"("projectID"),
	FOREIGN KEY("userID") REFERENCES "User"("userID")
);
COMMIT;
