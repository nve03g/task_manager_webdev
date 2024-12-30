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
	PRIMARY KEY("projectID" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "Task" (
	"taskID"	INTEGER NOT NULL UNIQUE,
	"name"	TEXT NOT NULL,
	"status"	TEXT NOT NULL,
	"projectID"	INTEGER NOT NULL,
	PRIMARY KEY("taskID" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "Task_User" (
	"task_X_user_ID"	INTEGER NOT NULL UNIQUE,
	"taskID"	INTEGER NOT NULL,
	"userID"	INTEGER NOT NULL,
	"role"	TEXT NOT NULL,
	PRIMARY KEY("task_X_user_ID" AUTOINCREMENT),
	FOREIGN KEY("userID") REFERENCES "User"("userID")
);
CREATE TABLE IF NOT EXISTS "Project_User" (
	"project_X_user_ID"	INTEGER NOT NULL UNIQUE,
	"projectID"	INTEGER NOT NULL,
	"userID"	INTEGER NOT NULL,
	"role"	TEXT NOT NULL,
	PRIMARY KEY("project_X_user_ID" AUTOINCREMENT),
	FOREIGN KEY("projectID") REFERENCES "Project"("projectID")
);
-- INSERT INTO "User" ("userID","username","password") VALUES (1,'user_1','password'),
--  (2,'user_2','password'),
--  (3,'Nellie','password'),
--  (4,'Robbe','password'),
--  (5,'Victor','password'),
--  (6,'Joke','password'),
--  (7,'Elien','password'),
--  (8,'Katrien','password');
-- INSERT INTO "Project" ("projectID","title") VALUES (1,'schooltasks'),
--  (2,'kitchen tasks'),
--  (3,'health');
-- INSERT INTO "Task" ("taskID","name","status","projectID") VALUES (1,'project multimedia','busy',1),
--  (2,'presentatie turbo coding','urgent',1),
--  (3,'go to the grocery store','',2),
--  (4,'meeting nr.5 with Pfizer','preparing',1),
--  (5,'make dentist appointment','',3),
--  (6,'go to the hairdresser','',3),
--  (7,'clean the dishes','',2),
--  (8,'deep-clean fridge and freezer','',2),
--  (9,'rinse dishwasher and hooter filters','',2);
-- INSERT INTO "Task_User" ("task_X_user_ID","taskID","userID","role") VALUES (1,1,3,'admin'),
--  (2,1,4,'admin'),
--  (3,2,3,'admin'),
--  (4,2,5,'general'),
--  (5,3,3,'admin'),
--  (6,4,3,'admin'),
--  (7,5,3,'admin'),
--  (8,5,8,'general'),
--  (9,5,6,'general'),
--  (10,6,3,'admin'),
--  (11,7,3,'admin'),
--  (12,7,6,'admin'),
--  (13,7,7,'admin'),
--  (14,8,3,'admin'),
--  (15,8,6,'admin'),
--  (16,8,8,'admin'),
--  (17,9,3,'admin');
-- INSERT INTO "Project_User" ("project_X_user_ID","projectID","userID","role") VALUES (1,1,1,'admin'),
--  (2,1,3,'admin'),
--  (3,1,4,'general'),
--  (4,1,5,'general'),
--  (5,2,3,'admin'),
--  (6,2,6,'general'),
--  (7,2,7,'general'),
--  (8,2,8,'general'),
--  (9,3,3,'admin'),
--  (10,3,6,'general'),
--  (11,3,8,'general');
COMMIT;
