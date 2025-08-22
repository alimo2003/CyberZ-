-- Database Creation Script for CyberZ
-- Generated on: 2025-06-28

-- Create schema if it doesn't exist
IF NOT EXISTS (SELECT * FROM sys.schemas WHERE name = 'dbo')
BEGIN
    EXEC('CREATE SCHEMA [dbo]')
END
GO

-- Create tables

-- Table: dbo.users
CREATE TABLE [dbo].[users] (
    [id] INT IDENTITY(1,1) NOT NULL,
    [username] NVARCHAR(100) NOT NULL,
    [email] NVARCHAR(200) NOT NULL,
    [password_hash] NVARCHAR(510) NOT NULL,
    [salt] NVARCHAR(200) NOT NULL,
    [first_name] NVARCHAR(100) NULL,
    [last_name] NVARCHAR(100) NULL,
    [is_active] BIT NULL DEFAULT 1,
    [is_verified] BIT NULL DEFAULT 0,
    [last_login] DATETIMEOFFSET(7) NULL,
    [created_at] DATETIMEOFFSET(7) NOT NULL,
    [updated_at] DATETIMEOFFSET(7) NOT NULL,
    [role_id] INT NOT NULL,
    [failed_login_attempts] INT NULL,
    [last_failed_login] DATETIMEOFFSET(7) NULL,
    CONSTRAINT [PK_users] PRIMARY KEY CLUSTERED ([id] ASC)
);

-- Table: dbo.roles
CREATE TABLE [dbo].[roles] (
    [id] INT IDENTITY(1,1) NOT NULL,
    [name] NVARCHAR(100) NOT NULL,
    [description] NVARCHAR(MAX) NULL,
    [created_at] DATETIMEOFFSET(7) NULL,
    CONSTRAINT [PK_roles] PRIMARY KEY CLUSTERED ([id] ASC)
);

-- Table: dbo.permissions
CREATE TABLE [dbo].[permissions] (
    [id] INT IDENTITY(1,1) NOT NULL,
    [name] NVARCHAR(100) NOT NULL,
    [description] NVARCHAR(MAX) NULL,
    [created_at] DATETIMEOFFSET(7) NULL,
    CONSTRAINT [PK_permissions] PRIMARY KEY CLUSTERED ([id] ASC)
);

-- Table: dbo.role_permissions
CREATE TABLE [dbo].[role_permissions] (
    [id] INT IDENTITY(1,1) NOT NULL,
    [role_id] INT NOT NULL,
    [permission_id] INT NOT NULL,
    [created_at] DATETIMEOFFSET(7) NULL,
    CONSTRAINT [PK_role_permissions] PRIMARY KEY CLUSTERED ([id] ASC)
);

-- Table: dbo.user_roles
CREATE TABLE [dbo].[user_roles] (
    [id] INT IDENTITY(1,1) NOT NULL,
    [user_id] INT NOT NULL,
    [role_id] INT NOT NULL,
    [created_at] DATETIMEOFFSET(7) NULL,
    CONSTRAINT [PK_user_roles] PRIMARY KEY CLUSTERED ([id] ASC)
);

-- Table: dbo.MFA_Codes
CREATE TABLE [dbo].[MFA_Codes] (
    [id] INT IDENTITY(1,1) NOT NULL,
    [user_id] INT NOT NULL,
    [code] NVARCHAR(510) NOT NULL,
    [created_at] DATETIME NOT NULL,
    [expires_at] DATETIME NOT NULL,
    [is_used] BIT NOT NULL DEFAULT 0,
    CONSTRAINT [PK_MFA_Codes] PRIMARY KEY CLUSTERED ([id] ASC)
);

-- Table: dbo.ScanResults
CREATE TABLE [dbo].[ScanResults] (
    [id] INT IDENTITY(1,1) NOT NULL,
    [scan_type] VARCHAR(20) NOT NULL,
    [target] VARCHAR(255) NOT NULL,
    [result] NVARCHAR(MAX) NOT NULL,
    [created_at] DATETIME2(7) NULL DEFAULT GETDATE(),
    [updated_at] DATETIME2(7) NULL DEFAULT GETDATE(),
    CONSTRAINT [PK_ScanResults] PRIMARY KEY CLUSTERED ([id] ASC)
);

-- Table: dbo.scan_metadata
CREATE TABLE [dbo].[scan_metadata] (
    [id] INT IDENTITY(1,1) NOT NULL,
    [scan_id] VARCHAR(100) NOT NULL,
    [hash_value] VARCHAR(64) NOT NULL,
    [hash_type] VARCHAR(10) NOT NULL,
    [scan_date] DATETIME NOT NULL,
    [created_at] DATETIME NULL DEFAULT GETDATE(),
    [updated_at] DATETIME NULL DEFAULT GETDATE(),
    CONSTRAINT [PK_scan_metadata] PRIMARY KEY CLUSTERED ([id] ASC)
);

-- Table: dbo.virus_total_scans
CREATE TABLE [dbo].[virus_total_scans] (
    [id] INT IDENTITY(1,1) NOT NULL,
    [scan_id] VARCHAR(100) NOT NULL,
    [hash_value] VARCHAR(64) NOT NULL,
    [hash_type] VARCHAR(10) NOT NULL,
    [scan_date] DATETIME NOT NULL,
    [positives] INT NOT NULL,
    [total] INT NOT NULL,
    [detection_rate] FLOAT(53) NOT NULL,
    [threat_level] VARCHAR(20) NOT NULL,
    [malware_names] NVARCHAR(MAX) NULL,
    [malware_types] NVARCHAR(MAX) NULL,
    [permalink] VARCHAR(255) NULL,
    [created_at] DATETIME NULL DEFAULT GETDATE(),
    [raw_result] NVARCHAR(MAX) NULL,
    CONSTRAINT [PK_virus_total_scans] PRIMARY KEY CLUSTERED ([id] ASC)
);

-- Table: dbo.virustotal_detailed_results
CREATE TABLE [dbo].[virustotal_detailed_results] (
    [id] INT IDENTITY(1,1) NOT NULL,
    [scan_metadata_id] INT NOT NULL,
    [raw_response] NVARCHAR(MAX) NOT NULL,
    [created_at] DATETIME NOT NULL DEFAULT GETDATE(),
    [updated_at] DATETIME NOT NULL DEFAULT GETDATE(),
    CONSTRAINT [PK_virustotal_detailed_results] PRIMARY KEY CLUSTERED ([id] ASC)
);

-- Table: dbo.virustotal_detections
CREATE TABLE [dbo].[virustotal_detections] (
    [id] INT IDENTITY(1,1) NOT NULL,
    [virustotal_scan_id] INT NOT NULL,
    [vendor_name] NVARCHAR(200) NOT NULL,
    [category] VARCHAR(50) NULL,
    [result] NVARCHAR(510) NULL,
    [method] VARCHAR(50) NULL,
    [update_time] DATETIME NULL,
    [created_at] DATETIME NOT NULL DEFAULT GETDATE(),
    CONSTRAINT [PK_virustotal_detections] PRIMARY KEY CLUSTERED ([id] ASC)
);

-- Table: dbo.AttackLogs
CREATE TABLE [dbo].[AttackLogs] (
    [LogID] INT IDENTITY(1,1) NOT NULL,
    [Timestamp] DATETIME2(7) NOT NULL,
    [AttackType] NVARCHAR(100) NOT NULL,
    [SourceIP] NVARCHAR(100) NOT NULL,
    [Payload] NVARCHAR(MAX) NOT NULL,
    [Severity] TINYINT NOT NULL,
    [Status] NVARCHAR(40) NOT NULL,
    [UserAgent] NVARCHAR(510) NULL,
    [Path] NVARCHAR(510) NULL,
    [Method] NVARCHAR(20) NULL,
    [CreatedAt] DATETIME2(7) NOT NULL DEFAULT GETDATE(),
    CONSTRAINT [PK_AttackLogs] PRIMARY KEY CLUSTERED ([LogID] ASC)
);

-- Table: dbo.AttackStats
CREATE TABLE [dbo].[AttackStats] (
    [StatID] INT IDENTITY(1,1) NOT NULL,
    [TimeframeType] NVARCHAR(20) NOT NULL,
    [LastUpdated] DATETIME2(7) NOT NULL,
    [SQLInjectionCount] INT NOT NULL DEFAULT 0,
    [XSSCount] INT NOT NULL DEFAULT 0,
    [BlockedCount] INT NOT NULL DEFAULT 0,
    [DetectedCount] INT NOT NULL DEFAULT 0,
    [CreatedAt] DATETIME2(7) NOT NULL DEFAULT GETDATE(),
    [UpdatedAt] DATETIME2(7) NOT NULL DEFAULT GETDATE(),
    CONSTRAINT [PK_AttackStats] PRIMARY KEY CLUSTERED ([StatID] ASC)
);

-- Table: dbo.AuthLogs
CREATE TABLE [dbo].[AuthLogs] (
    [id] INT IDENTITY(1,1) NOT NULL,
    [user_id] INT NOT NULL,
    [action] VARCHAR(50) NOT NULL,
    [ip_address] VARCHAR(45) NULL,
    [user_agent] NVARCHAR(MAX) NULL,
    [status] VARCHAR(20) NOT NULL,
    [created_at] DATETIMEOFFSET(7) NOT NULL DEFAULT SYSDATETIMEOFFSET(),
    CONSTRAINT [PK_AuthLogs] PRIMARY KEY CLUSTERED ([id] ASC)
);

-- Table: dbo.DailyAttackPatterns
CREATE TABLE [dbo].[DailyAttackPatterns] (
    [PatternID] INT IDENTITY(1,1) NOT NULL,
    [DayOfWeek] INT NOT NULL,
    [SQLInjectionCount] INT NOT NULL DEFAULT 0,
    [XSSCount] INT NOT NULL DEFAULT 0,
    [RecordDate] DATE NOT NULL,
    [CreatedAt] DATETIME2(7) NOT NULL DEFAULT GETDATE(),
    [UpdatedAt] DATETIME2(7) NOT NULL DEFAULT GETDATE(),
    CONSTRAINT [PK_DailyAttackPatterns] PRIMARY KEY CLUSTERED ([PatternID] ASC)
);

-- Table: dbo.departments
CREATE TABLE [dbo].[departments] (
    [id] INT IDENTITY(1,1) NOT NULL,
    [name] VARCHAR(100) NOT NULL,
    [description] VARCHAR(MAX) NULL,
    [created_at] DATETIME NOT NULL DEFAULT GETDATE(),
    [updated_at] DATETIME NOT NULL DEFAULT GETDATE(),
    CONSTRAINT [PK_departments] PRIMARY KEY CLUSTERED ([id] ASC)
);

-- Table: dbo.HourlyAttackPatterns
CREATE TABLE [dbo].[HourlyAttackPatterns] (
    [PatternID] INT IDENTITY(1,1) NOT NULL,
    [Hour] INT NOT NULL,
    [SQLInjectionCount] INT NOT NULL DEFAULT 0,
    [XSSCount] INT NOT NULL DEFAULT 0,
    [RecordDate] DATE NOT NULL,
    [CreatedAt] DATETIME2(7) NOT NULL DEFAULT GETDATE(),
    [UpdatedAt] DATETIME2(7) NOT NULL DEFAULT GETDATE(),
    CONSTRAINT [PK_HourlyAttackPatterns] PRIMARY KEY CLUSTERED ([PatternID] ASC)
);

-- Table: dbo.malwarebazaar_scans
CREATE TABLE [dbo].[malwarebazaar_scans] (
    [id] INT IDENTITY(1,1) NOT NULL,
    [scan_id] VARCHAR(100) NOT NULL,
    [hash_value] VARCHAR(64) NOT NULL,
    [hash_type] VARCHAR(10) NOT NULL,
    [file_name] NVARCHAR(255) NULL,
    [file_type] VARCHAR(100) NULL,
    [file_size] INT NULL,
    [first_seen] DATETIME NULL,
    [last_seen] DATETIME NULL,
    [signature] NVARCHAR(255) NULL,
    [reporter] NVARCHAR(255) NULL,
    [delivery_method] NVARCHAR(100) NULL,
    [intelligence] NVARCHAR(MAX) NULL,
    [comments] NVARCHAR(MAX) NULL,
    [created_at] DATETIME NOT NULL DEFAULT GETDATE(),
    [updated_at] DATETIME NOT NULL DEFAULT GETDATE(),
    CONSTRAINT [PK_malwarebazaar_scans] PRIMARY KEY CLUSTERED ([id] ASC)
);

-- Table: dbo.malwarebazaar_tags
CREATE TABLE [dbo].[malwarebazaar_tags] (
    [id] INT IDENTITY(1,1) NOT NULL,
    [malwarebazaar_scan_id] INT NOT NULL,
    [tag] NVARCHAR(200) NOT NULL,
    [created_at] DATETIME NOT NULL DEFAULT GETDATE(),
    CONSTRAINT [PK_malwarebazaar_tags] PRIMARY KEY CLUSTERED ([id] ASC)
);

-- Table: dbo.virustotal_scans (updated with additional columns)
CREATE TABLE [dbo].[virustotal_scans] (
    [id] INT IDENTITY(1,1) NOT NULL,
    [scan_metadata_id] INT NOT NULL,
    [scan_id] VARCHAR(100) NOT NULL,
    [positives] INT NOT NULL,
    [total] INT NOT NULL,
    [detection_rate] FLOAT NOT NULL,
    [threat_level] VARCHAR(20) NOT NULL,
    [permalink] VARCHAR(255) NULL,
    [last_analysis_date] DATETIME NULL,
    [first_submission_date] DATETIME NULL,
    [last_submission_date] DATETIME NULL,
    [times_submitted] INT NULL,
    [reputation] INT NULL,
    [tags] NVARCHAR(MAX) NULL,
    [created_at] DATETIME NOT NULL DEFAULT GETDATE(),
    [updated_at] DATETIME NOT NULL DEFAULT GETDATE(),
    CONSTRAINT [PK_virustotal_scans] PRIMARY KEY CLUSTERED ([id] ASC)
);

-- Table: dbo.ModelFeedback
CREATE TABLE [dbo].[ModelFeedback] (
    [FeedbackID] INT IDENTITY(1,1) NOT NULL,
    [Timestamp] DATETIME2(7) NOT NULL,
    [InputText] NVARCHAR(MAX) NOT NULL,
    [PredictedClass] NVARCHAR(100) NOT NULL,
    [ActualClass] NVARCHAR(100) NOT NULL,
    [SubmittedByUserID] INT NULL,
    CONSTRAINT [PK_ModelFeedback] PRIMARY KEY CLUSTERED ([FeedbackID] ASC)
);

-- Table: dbo.ModelHealth
CREATE TABLE [dbo].[ModelHealth] (
    [MetricID] INT IDENTITY(1,1) NOT NULL,
    [Timestamp] DATETIME2(7) NOT NULL,
    [Accuracy] FLOAT(53) NOT NULL,
    [Precision] FLOAT(53) NOT NULL,
    [Recall] FLOAT(53) NOT NULL,
    [F1Score] FLOAT(53) NOT NULL,
    [ConceptDrift] FLOAT(53) NULL,
    [TrainingDataSize] INT NOT NULL,
    CONSTRAINT [PK_ModelHealth] PRIMARY KEY CLUSTERED ([MetricID] ASC)
);

-- Create foreign key constraints

-- Add foreign key for users.role_id
ALTER TABLE [dbo].[users] WITH CHECK ADD CONSTRAINT [FK_users_roles] 
    FOREIGN KEY([role_id]) REFERENCES [dbo].[roles] ([id]) ON DELETE NO ACTION;

-- Add foreign key for MFA_Codes.user_id
ALTER TABLE [dbo].[MFA_Codes] WITH CHECK ADD CONSTRAINT [FK_MFA_Codes_users] 
    FOREIGN KEY([user_id]) REFERENCES [dbo].[users] ([id]) ON DELETE CASCADE;

-- Add foreign key for role_permissions.role_id
ALTER TABLE [dbo].[role_permissions] WITH CHECK ADD CONSTRAINT [FK_role_permissions_roles] 
    FOREIGN KEY([role_id]) REFERENCES [dbo].[roles] ([id]) ON DELETE CASCADE;

-- Add foreign key for role_permissions.permission_id
ALTER TABLE [dbo].[role_permissions] WITH CHECK ADD CONSTRAINT [FK_role_permissions_permissions] 
    FOREIGN KEY([permission_id]) REFERENCES [dbo].[permissions] ([id]) ON DELETE CASCADE;

-- Add foreign key for user_roles.user_id
ALTER TABLE [dbo].[user_roles] WITH CHECK ADD CONSTRAINT [FK_user_roles_users] 
    FOREIGN KEY([user_id]) REFERENCES [dbo].[users] ([id]) ON DELETE CASCADE;

-- Add foreign key for user_roles.role_id
ALTER TABLE [dbo].[user_roles] WITH CHECK ADD CONSTRAINT [FK_user_roles_roles] 
    FOREIGN KEY([role_id]) REFERENCES [dbo].[roles] ([id]) ON DELETE CASCADE;

-- Add foreign key for virustotal_detailed_results.scan_metadata_id
ALTER TABLE [dbo].[virustotal_detailed_results] WITH CHECK ADD CONSTRAINT [FK_virustotal_detailed_results_scan_metadata] 
    FOREIGN KEY([scan_metadata_id]) REFERENCES [dbo].[scan_metadata] ([id]) ON DELETE CASCADE;

-- Add foreign key for virustotal_detections.virustotal_scan_id
ALTER TABLE [dbo].[virustotal_detections] WITH CHECK ADD CONSTRAINT [FK_virustotal_detections_virus_total_scans] 
    FOREIGN KEY([virustotal_scan_id]) REFERENCES [dbo].[virus_total_scans] ([id]) ON DELETE CASCADE;

-- Add foreign key for malwarebazaar_tags.malwarebazaar_scan_id
ALTER TABLE [dbo].[malwarebazaar_tags] WITH CHECK ADD CONSTRAINT [FK_malwarebazaar_tags_scans] 
    FOREIGN KEY([malwarebazaar_scan_id]) REFERENCES [dbo].[malwarebazaar_scans] ([id]) ON DELETE CASCADE;

-- Add foreign key for virustotal_scans.scan_metadata_id
ALTER TABLE [dbo].[virustotal_scans] WITH CHECK ADD CONSTRAINT [FK_virustotal_scans_metadata] 
    FOREIGN KEY([scan_metadata_id]) REFERENCES [dbo].[scan_metadata] ([id]) ON DELETE CASCADE;

-- Add foreign key for AuthLogs.user_id
ALTER TABLE [dbo].[AuthLogs] WITH CHECK ADD CONSTRAINT [FK_AuthLogs_users] 
    FOREIGN KEY([user_id]) REFERENCES [dbo].[users] ([id]) ON DELETE CASCADE;

-- Add indexes for better performance
CREATE NONCLUSTERED INDEX [IX_users_username] ON [dbo].[users] ([username]);
CREATE NONCLUSTERED INDEX [IX_users_email] ON [dbo].[users] ([email]);
CREATE NONCLUSTERED INDEX [IX_roles_name] ON [dbo].[roles] ([name]);
CREATE NONCLUSTERED INDEX [IX_MFA_Codes_user_id] ON [dbo].[MFA_Codes] ([user_id]);
CREATE NONCLUSTERED INDEX [IX_scan_metadata_hash_value] ON [dbo].[scan_metadata] ([hash_value]);
CREATE NONCLUSTERED INDEX [IX_virus_total_scans_hash_value] ON [dbo].[virus_total_scans] ([hash_value]);
CREATE NONCLUSTERED INDEX [IX_malwarebazaar_scans_hash] ON [dbo].[malwarebazaar_scans] ([hash_value]);
CREATE NONCLUSTERED INDEX [IX_malwarebazaar_tags_scan_id] ON [dbo].[malwarebazaar_tags] ([malwarebazaar_scan_id]);
CREATE NONCLUSTERED INDEX [IX_virustotal_detections_scan_id] ON [dbo].[virustotal_detections] ([virustotal_scan_id]);
CREATE NONCLUSTERED INDEX [IX_virustotal_scans_metadata] ON [dbo].[virustotal_scans] ([scan_metadata_id]);

-- Indexes for AttackLogs
CREATE NONCLUSTERED INDEX [IX_AttackLogs_Timestamp] ON [dbo].[AttackLogs] ([Timestamp]);
CREATE NONCLUSTERED INDEX [IX_AttackLogs_AttackType] ON [dbo].[AttackLogs] ([AttackType]);
CREATE NONCLUSTERED INDEX [IX_AttackLogs_SourceIP] ON [dbo].[AttackLogs] ([SourceIP]);

-- Indexes for AttackStats
CREATE NONCLUSTERED INDEX [IX_AttackStats_TimeframeType] ON [dbo].[AttackStats] ([TimeframeType]);

-- Indexes for AuthLogs
CREATE NONCLUSTERED INDEX [IX_AuthLogs_user_id] ON [dbo].[AuthLogs] ([user_id]);
CREATE NONCLUSTERED INDEX [IX_AuthLogs_created_at] ON [dbo].[AuthLogs] ([created_at]);

-- Indexes for DailyAttackPatterns
CREATE NONCLUSTERED INDEX [IX_DailyAttackPatterns_DayOfWeek] ON [dbo].[DailyAttackPatterns] ([DayOfWeek]);
CREATE NONCLUSTERED INDEX [IX_DailyAttackPatterns_RecordDate] ON [dbo].[DailyAttackPatterns] ([RecordDate]);

-- Indexes for HourlyAttackPatterns
CREATE NONCLUSTERED INDEX [IX_HourlyAttackPatterns_Hour] ON [dbo].[HourlyAttackPatterns] ([Hour]);
CREATE NONCLUSTERED INDEX [IX_HourlyAttackPatterns_RecordDate] ON [dbo].[HourlyAttackPatterns] ([RecordDate]);

-- Add default roles
INSERT INTO [dbo].[roles] ([name], [description], [created_at])
VALUES 
    ('super_admin', 'Super Administrator with full access', GETDATE()),
    ('admin', 'Administrator with elevated privileges', GETDATE()),
    ('user', 'Standard user with basic access', GETDATE());

-- Add default admin user with password: Admin@123
-- First disable identity insert to allow specific ID
SET IDENTITY_INSERT [dbo].[users] ON;

INSERT INTO [dbo].[users] (
    [id],
    [username], 
    [email], 
    [password_hash], 
    [salt], 
    [first_name], 
    [last_name], 
    [is_active], 
    [is_verified], 
    [created_at], 
    [updated_at], 
    [role_id]
)
VALUES (
    1,  -- Explicit ID for the admin user
    'admin', 
    'admin@cyberz.com', 
    '2C1F4ED4C3E5A7E61CF88D70F3D5D762F2DBE31833EB1F4AEB9B446A0D6E8C3A',
    'F348864A-47CB-4612-A14E-E134B0143905',
    'System', 
    'Administrator', 
    1, 
    1, 
    GETDATE(), 
    GETDATE(), 
    1  -- ID of the super_admin role
);

-- Re-enable identity insert
SET IDENTITY_INSERT [dbo].[users] OFF;

-- Assign super_admin role to the admin user
INSERT INTO [dbo].[user_roles] ([user_id], [role_id], [created_at])
VALUES (1, 1, GETDATE());

-- Add default permissions (customize as needed)
INSERT INTO [dbo].[permissions] ([name], [description], [created_at])
VALUES 
    ('manage_users', 'Can manage users', GETDATE()),
    ('manage_roles', 'Can manage roles and permissions', GETDATE()),
    ('view_reports', 'Can view reports and analytics', GETDATE()),
    ('perform_scans', 'Can perform security scans', GETDATE()),
    ('manage_settings', 'Can manage system settings', GETDATE());

-- Assign all permissions to super_admin role
INSERT INTO [dbo].[role_permissions] ([role_id], [permission_id], [created_at])
SELECT 1, [id], GETDATE() FROM [dbo].[permissions];

-- Assign basic permissions to admin role
INSERT INTO [dbo].[role_permissions] ([role_id], [permission_id], [created_at])
SELECT 2, [id], GETDATE() FROM [dbo].[permissions] 
WHERE [name] IN ('manage_users', 'view_reports', 'perform_scans');

-- Assign basic permissions to user role
INSERT INTO [dbo].[role_permissions] ([role_id], [permission_id], [created_at])
SELECT 3, [id], GETDATE() FROM [dbo].[permissions] 
WHERE [name] IN ('view_reports', 'perform_scans');

-- Add a message to indicate successful script completion
PRINT 'Database schema created successfully!';
