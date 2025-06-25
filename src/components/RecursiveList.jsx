// src/components/RecursiveList.jsx

export default function RecursiveList({ node }) {
    function getDocUrl(doc) {
      return `/${doc.slug}`;
    }
  
    function getSlugTail(doc) {
      return doc.slug.split('/').at(-1);
    }
  
    return (
      <>
        {Object.entries(node).map(([key, value]) => {
          if (key === '__docs') return null;
  
          const docs = value.__docs ?? [];
  
          const indexDoc = docs.find((doc) => getSlugTail(doc) === 'index');
          const otherDocs = docs.filter((doc) => getSlugTail(doc) !== 'index');
  
          return (
            <li key={key}>
              {indexDoc ? (
                <a href={getDocUrl(indexDoc)}><strong>{key}/</strong></a>
              ) : (
                <strong>{key}/</strong>
              )}
              <ul>
                {otherDocs.map((doc) => (
                  <li key={doc.slug}>
                    <a href={getDocUrl(doc)}>{doc.data.title ?? doc.slug}</a>
                  </li>
                ))}
                {/* 递归子目录 */}
                <RecursiveList node={value} />
              </ul>
            </li>
          );
        })}
      </>
    );
  }  