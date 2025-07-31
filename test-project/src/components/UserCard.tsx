/**
 * User card component
 */

import React from 'react';

interface User {
  id: string;
  email: string;
  role: string;
}

interface UserCardProps {
  user: User;
  onDelete?: (userId: string) => void;
}

/**
 * React component for displaying user information
 */
export function UserCard({ user, onDelete }: UserCardProps) {
  const handleDelete = () => {
    if (onDelete) {
      onDelete(user.id);
    }
  };

  return (
    <div className="user-card">
      <h3>{user.email}</h3>
      <p>Role: {user.role}</p>
      <button onClick={handleDelete}>Delete User</button>
    </div>
  );
}

/**
 * Class-based React component example
 */
export class UserList extends React.Component<{ users: User[] }> {
  render() {
    return (
      <div className="user-list">
        {this.props.users.map(user => (
          <UserCard key={user.id} user={user} />
        ))}
      </div>
    );
  }
}

/**
 * Custom hook for user management
 */
export function useUserManagement() {
  const [users, setUsers] = React.useState<User[]>([]);
  const [loading, setLoading] = React.useState(false);

  const loadUsers = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/users');
      const data = await response.json();
      setUsers(data.users);
    } catch (error) {
      console.error('Failed to load users:', error);
    } finally {
      setLoading(false);
    }
  };

  const deleteUser = async (userId: string) => {
    try {
      const response = await fetch(`/api/users/${userId}`, {
        method: 'DELETE'
      });
      
      if (response.ok) {
        setUsers(prev => prev.filter(u => u.id !== userId));
      }
    } catch (error) {
      console.error('Failed to delete user:', error);
    }
  };

  return {
    users,
    loading,
    loadUsers,
    deleteUser
  };
}

export default UserCard;