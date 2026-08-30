import React from 'react';

export function FormField({ label, name, hint, ...input }: { label: string; name: string; hint?: string } & Omit<React.InputHTMLAttributes<HTMLInputElement>, 'name'>) {
  const hintId = hint ? `${name}-hint` : undefined;
  return (
    <div className="form-field">
      <label htmlFor={name}>{label}</label>
      <input {...input} id={name} name={name} aria-describedby={hintId} />
      {hint ? <small id={hintId}>{hint}</small> : null}
    </div>
  );
}
