<?php
namespace Mnb\SecurityCore\Database;

final class DatabaseAuditEvents
{
    public const CONNECTION_CHECKED = 'db.connection.checked';
    public const CONNECTION_FAILED = 'db.connection.failed';
    public const QUERY_ALLOWED = 'db.query.allowed';
    public const QUERY_BLOCKED = 'db.query.blocked';
    public const QUERY_SLOW = 'db.query.slow';
    public const SEARCH_ALLOWED = 'db.search.allowed';
    public const SEARCH_BLOCKED = 'db.search.blocked';
    public const CREATE_ALLOWED = 'db.create.allowed';
    public const UPDATE_ALLOWED = 'db.update.allowed';
    public const DELETE_SOFT = 'db.delete.soft';
    public const DELETE_HARD = 'db.delete.hard';
    public const RESTORE = 'db.restore';
    public const TRANSACTION_BEGIN = 'db.transaction.begin';
    public const TRANSACTION_COMMIT = 'db.transaction.commit';
    public const TRANSACTION_ROLLBACK = 'db.transaction.rollback';
    public const SCHEMA_PLAN_CREATED = 'db.schema.plan_created';
    public const SCHEMA_ALTER_ALLOWED = 'db.schema.alter_allowed';
    public const SCHEMA_ALTER_BLOCKED = 'db.schema.alter_blocked';
    public const PRIVILEGE_WARNING = 'db.privilege.warning';
}
